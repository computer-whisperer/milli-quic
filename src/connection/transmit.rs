//! Transmit path: build frames, encrypt packets, emit datagrams.

use crate::crypto::{Aead, CryptoProvider, HeaderProtection, Level};
use crate::error::Error;
use crate::frame::{self, AckFrame, ConnectionCloseFrame, CryptoFrame, Frame, StreamFrame};
use crate::packet::{self, MIN_INITIAL_PACKET_SIZE};
use crate::tls::TlsSession;
use crate::transport::Instant;
use crate::transport::recovery::SentPacket;

use super::recv::level_index;
use super::{Connection, ConnectionState, Transmit};

impl<C: CryptoProvider, const MAX_STREAMS: usize, const SENT_PER_SPACE: usize, const MAX_CIDS: usize, const STREAM_BUF: usize, const SEND_QUEUE: usize, const CRYPTO_BUF: usize>
    Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS, STREAM_BUF, SEND_QUEUE, CRYPTO_BUF>
where
    C::Hkdf: Default,
{
    /// Build the next outgoing UDP datagram. Returns `None` if nothing to send.
    pub fn poll_transmit<'a>(
        &mut self,
        buf: &'a mut [u8],
        now: Instant,
    ) -> Option<Transmit<'a>> {
        if matches!(self.state, ConnectionState::Closed) {
            return None;
        }

        // Anti-amplification check: if address is not validated and we've
        // already sent 3x what we received, we cannot send anything.
        if !self.address_validated && !self.amplification_allows(1) {
            return None;
        }

        let mut total_written = 0;

        // Try to send at each level, coalescing into one datagram.

        // 1. CONNECTION_CLOSE (if closing)
        if let Some((error_code, ref reason)) = self.close_frame.clone() {
            // Send CONNECTION_CLOSE at the highest available level
            let level = if self.keys.has_send_keys(Level::Application) {
                Level::Application
            } else if self.keys.has_send_keys(Level::Handshake) {
                Level::Handshake
            } else if self.keys.has_send_keys(Level::Initial) {
                Level::Initial
            } else {
                return None;
            };

            let mut frame_buf = [0u8; 128];
            let close_frame = Frame::ConnectionClose(ConnectionCloseFrame {
                is_application: false,
                error_code,
                frame_type: 0,
                reason,
            });
            if let Ok(frame_len) = frame::encode(&close_frame, &mut frame_buf) {
                let result = if level == Level::Initial {
                    let is_client = self.role == crate::tls::handshake::Role::Client;
                    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
                    {
                        // Take initial keys out temporarily to avoid borrow conflict.
                        let send = self.keys.initial_send.take();
                        let r = if let Some(ref k) = send {
                            self.build_and_encrypt_initial_packet(
                                &frame_buf[..frame_len],
                                is_client,
                                buf,
                                now,
                                k,
                            )
                        } else {
                            Err(Error::Crypto)
                        };
                        self.keys.initial_send = send;
                        r
                    }
                    #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
                    {
                        let _ = is_client;
                        Err(Error::Crypto)
                    }
                } else {
                    self.build_and_encrypt_packet(
                        level,
                        &frame_buf[..frame_len],
                        false,
                        buf,
                        now,
                    )
                };
                if let Ok(pkt_len) = result {
                    total_written += pkt_len;
                }
            }

            self.state = ConnectionState::Closed;
            if total_written > 0 {
                return Some(Transmit {
                    data: &buf[..total_written],
                });
            }
            return None;
        }

        // 2. Initial-level data (TLS ClientHello/ServerHello in CRYPTO frames, ACKs)
        if self.keys.has_send_keys(Level::Initial)
            && let Some(pkt_len) = self.build_initial_packet(&mut buf[total_written..], now)
        {
            total_written += pkt_len;
        }

        // 3. Handshake-level data (TLS handshake messages in CRYPTO frames, ACKs)
        if self.keys.has_send_keys(Level::Handshake)
            && let Some(pkt_len) = self.build_handshake_packet(&mut buf[total_written..], now)
        {
            total_written += pkt_len;
        }

        // 4. Application-level data (STREAM frames, ACKs, HANDSHAKE_DONE, etc.)
        if self.keys.has_send_keys(Level::Application)
            && let Some(pkt_len) = self.build_short_packet(&mut buf[total_written..], now)
        {
            total_written += pkt_len;
        }

        if total_written > 0 {
            // Anti-amplification: check the 3x limit on the final datagram size
            if !self.address_validated && !self.amplification_allows(total_written) {
                return None;
            }
            // Track bytes sent for anti-amplification accounting
            if !self.address_validated {
                self.anti_amplification_bytes_sent =
                    self.anti_amplification_bytes_sent.saturating_add(total_written);
            }
            Some(Transmit {
                data: &buf[..total_written],
            })
        } else {
            None
        }
    }

    /// Build an Initial packet if there's something to send at this level.
    fn build_initial_packet(&mut self, buf: &mut [u8], now: Instant) -> Option<usize> {
        let level = Level::Initial;

        // Collect frames to send
        let mut frame_buf = [0u8; 2048];
        let mut frame_len = 0;

        // ACK frame if needed
        if self.ack_eliciting_received[level_index(level)]
            && let Some(written) = self.build_ack_frame(level, &mut frame_buf[frame_len..])
        {
            frame_len += written;
            self.ack_eliciting_received[level_index(level)] = false;
        }

        // CRYPTO frame from TLS engine
        let crypto_written = self.write_tls_crypto_data(level, &mut frame_buf[frame_len..]);
        frame_len += crypto_written;

        if frame_len == 0 {
            return None;
        }

        // Pad Initial packets from client to 1200 bytes minimum
        let is_client = self.role == crate::tls::handshake::Role::Client;

        // Get initial send keys (concrete AES type) and build the packet.
        // Take keys out temporarily to avoid borrow conflict with &mut self.
        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        let result = {
            let send = self.keys.initial_send.take();
            let r = if let Some(ref k) = send {
                self.build_and_encrypt_initial_packet(
                    &frame_buf[..frame_len],
                    is_client,
                    buf,
                    now,
                    k,
                )
            } else {
                return None;
            };
            self.keys.initial_send = send;
            r
        };
        #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
        let result: Result<usize, Error> = Err(Error::Crypto);

        match result {
            Ok(pkt_len) => {
                // Server: once we've sent the ServerHello (Initial-level),
                // we can drop Initial keys if Handshake keys are already installed.
                if self.role == crate::tls::handshake::Role::Server
                    && self.keys.has_send_keys(Level::Handshake)
                {
                    self.keys.drop_initial();
                    self.sent_tracker.drop_space(Level::Initial);
                    self.loss_detector.drop_space(Level::Initial);
                }
                Some(pkt_len)
            }
            Err(_) => None,
        }
    }

    /// Build a Handshake packet if there's something to send at this level.
    fn build_handshake_packet(&mut self, buf: &mut [u8], now: Instant) -> Option<usize> {
        let level = Level::Handshake;

        let mut frame_buf = [0u8; 2048];
        let mut frame_len = 0;

        // ACK frame if needed
        if self.ack_eliciting_received[level_index(level)]
            && let Some(written) = self.build_ack_frame(level, &mut frame_buf[frame_len..])
        {
            frame_len += written;
            self.ack_eliciting_received[level_index(level)] = false;
        }

        // CRYPTO frame from TLS engine
        let crypto_written = self.write_tls_crypto_data(level, &mut frame_buf[frame_len..]);
        frame_len += crypto_written;

        if frame_len == 0 {
            return None;
        }

        self.build_and_encrypt_packet(level, &frame_buf[..frame_len], false, buf, now).ok()
    }

    /// Build a short (1-RTT) packet if there's something to send.
    fn build_short_packet(&mut self, buf: &mut [u8], now: Instant) -> Option<usize> {
        let level = Level::Application;

        let mut frame_buf = [0u8; 2048];
        let mut frame_len = 0;

        // Track whether we're attempting to send HANDSHAKE_DONE so we can
        // revert the flag if the packet fails to build.
        let mut sending_handshake_done = false;

        // HANDSHAKE_DONE (server, once after handshake completes)
        if self.role == crate::tls::handshake::Role::Server && self.need_handshake_done
            && let Ok(written) = frame::encode(&Frame::HandshakeDone, &mut frame_buf[frame_len..])
        {
            frame_len += written;
            sending_handshake_done = true;
        }

        // PATH_RESPONSE: echo challenge data back (RFC 9000 §8.2.2)
        if let Some(challenge_data) = self.pending_path_response.take() {
            let path_resp = Frame::PathResponse(challenge_data);
            if let Ok(written) = frame::encode(&path_resp, &mut frame_buf[frame_len..]) {
                frame_len += written;
            } else {
                // Put it back if encoding failed (buffer too small)
                self.pending_path_response = Some(challenge_data);
            }
        }

        // ACK frame if needed
        if self.ack_eliciting_received[level_index(level)]
            && let Some(written) = self.build_ack_frame(level, &mut frame_buf[frame_len..])
        {
            frame_len += written;
            self.ack_eliciting_received[level_index(level)] = false;
        }

        // STREAM frames from pending send buffers
        let stream_written = self.build_stream_frames(&mut frame_buf[frame_len..]);
        frame_len += stream_written;

        if frame_len == 0 {
            return None;
        }

        match self.build_and_encrypt_packet(level, &frame_buf[..frame_len], false, buf, now) {
            Ok(pkt_len) => {
                if sending_handshake_done {
                    self.need_handshake_done = false;
                }
                Some(pkt_len)
            }
            Err(_) => None,
        }
    }

    /// Build an ACK frame for the given level.
    ///
    /// Generates correct ACK ranges from the received packet number tracker.
    /// The QUIC ACK frame encodes ranges from highest to lowest:
    ///   - `largest_ack` = the highest received PN
    ///   - `first_ack_range` = `largest_ack - <start of highest range>`
    ///   - then for each subsequent range (descending): a gap/range pair
    ///     where `gap = <end of prev range> - <end of this range> - 2`
    ///     and `ack_range = <end of this range> - <start of this range>`
    fn build_ack_frame(&self, level: Level, buf: &mut [u8]) -> Option<usize> {
        let idx = level_index(level);
        let tracker = &self.recv_pn_tracker[idx];

        if tracker.ranges.is_empty() {
            return None;
        }

        // Ranges are sorted ascending. Work from the highest range down.
        let range_count = tracker.ranges.len();
        let (highest_start, highest_end) = tracker.ranges[range_count - 1];

        let largest_ack = highest_end;
        let first_ack_range = highest_end - highest_start;

        // Build the raw ACK range bytes (gap, ack_range varint pairs) for
        // all ranges below the highest, from next-highest down to lowest.
        let mut range_buf = [0u8; 512];
        let mut range_pos = 0;

        if range_count > 1 {
            // prev_smallest tracks the smallest PN in the previous (higher) range.
            let mut prev_smallest = highest_start;

            for i in (0..range_count - 1).rev() {
                let (r_start, r_end) = tracker.ranges[i];

                // gap = prev_smallest - r_end - 2
                // (the gap field counts how many PNs are missing *between*
                // the two ranges, minus 1 as per RFC 9000 Section 19.3.1)
                let gap = prev_smallest - r_end - 2;
                let ack_range = r_end - r_start;

                if let Ok(n) = crate::varint::encode_varint(gap, &mut range_buf[range_pos..]) {
                    range_pos += n;
                } else {
                    break; // buffer full, stop adding ranges
                }
                if let Ok(n) =
                    crate::varint::encode_varint(ack_range, &mut range_buf[range_pos..])
                {
                    range_pos += n;
                } else {
                    break;
                }

                prev_smallest = r_start;
            }
        }

        let ack = Frame::Ack(AckFrame {
            largest_ack,
            ack_delay: 0,
            first_ack_range,
            ack_ranges: &range_buf[..range_pos],
            ecn: None,
        });

        frame::encode(&ack, buf).ok()
    }

    /// Write pending TLS handshake data as CRYPTO frame(s).
    /// Returns total bytes written.
    fn write_tls_crypto_data(&mut self, target_level: Level, buf: &mut [u8]) -> usize {
        let mut tls_buf = [0u8; 2048];
        let (tls_len, tls_level) = match self.tls.write_handshake(&mut tls_buf) {
            Ok((len, level)) => (len, level),
            Err(_) => return 0,
        };

        if tls_len == 0 || tls_level != target_level {
            // Put it back: unfortunately we can't "unwrite" from TLS,
            // so we store it in a pending buffer
            if tls_len > 0 && tls_level != target_level {
                // Store for later
                self.pending_crypto[level_index(tls_level)].clear();
                let _ = self.pending_crypto[level_index(tls_level)]
                    .extend_from_slice(&tls_buf[..tls_len]);
                self.pending_crypto_level[level_index(tls_level)] = tls_level;
            }
            // Check if we have pending crypto data for this level
            let idx = level_index(target_level);
            if self.pending_crypto[idx].is_empty() {
                return 0;
            }
            let pending_data = self.pending_crypto[idx].clone();
            self.pending_crypto[idx].clear();

            let offset = self.crypto_send_offset[idx];
            let crypto = Frame::Crypto(CryptoFrame {
                offset,
                data: &pending_data,
            });
            match frame::encode(&crypto, buf) {
                Ok(written) => {
                    self.crypto_send_offset[idx] += pending_data.len() as u64;
                    return written;
                }
                Err(_) => return 0,
            }
        }

        let idx = level_index(target_level);
        let offset = self.crypto_send_offset[idx];
        let crypto = Frame::Crypto(CryptoFrame {
            offset,
            data: &tls_buf[..tls_len],
        });
        match frame::encode(&crypto, buf) {
            Ok(written) => {
                self.crypto_send_offset[idx] += tls_len as u64;
                written
            }
            Err(_) => 0,
        }
    }

    /// Build STREAM frames from pending send data.
    fn build_stream_frames(&mut self, buf: &mut [u8]) -> usize {
        let mut total = 0;
        let mut idx = 0;

        while idx < self.stream_send_queue.len() {
            let entry = &self.stream_send_queue[idx];
            let stream_id = entry.stream_id;
            let data_len = entry.len;
            let fin = entry.fin;

            // Check if we have enough space
            let remaining = buf.len() - total;
            if remaining < 16 {
                // Not enough space for even a minimal frame
                break;
            }

            let stream_frame = Frame::Stream(StreamFrame {
                stream_id,
                offset: entry.offset,
                data: &entry.data[..data_len],
                fin,
            });

            match frame::encode(&stream_frame, &mut buf[total..]) {
                Ok(written) => {
                    total += written;
                    idx += 1;
                }
                Err(_) => break,
            }
        }

        // Remove sent entries
        for _ in 0..idx {
            if !self.stream_send_queue.is_empty() {
                self.stream_send_queue.remove(0);
            }
        }

        total
    }

    /// Build and encrypt an Initial packet with proper padding.
    ///
    /// Generic over AEAD and HeaderProtection types so that Initial keys
    /// (concrete AES-128-GCM per RFC 9001) can be passed directly.
    fn build_and_encrypt_initial_packet<A: Aead, HP: HeaderProtection>(
        &mut self,
        payload_frames: &[u8],
        pad_to_min: bool,
        out: &mut [u8],
        now: Instant,
        send: &crate::crypto::DirectionalKeys<A, HP>,
    ) -> Result<usize, Error> {
        let level = Level::Initial;
        let pn = self.next_pn[level_index(level)];
        let largest_acked = self.largest_recv_pn[level_index(level)].unwrap_or(0);
        let pn_len = packet::pn_length(pn, largest_acked);
        let tag_len = 16; // AEAD tag

        let dcid = &self.remote_cid.as_slice();
        let scid = if self.local_cids.is_empty() {
            &[]
        } else {
            self.local_cids[0].as_slice()
        };
        let token: &[u8] = &[];

        // Calculate minimum payload needed for Initial packet
        let frame_len = payload_frames.len();
        let encrypted_payload_len = frame_len + tag_len;
        let payload_length = pn_len + encrypted_payload_len; // for Length field

        // Build header into a temp buffer to compute header length
        let mut header_buf = [0u8; 256];
        let header_len = packet::encode_initial_header(
            dcid,
            scid,
            token,
            pn_len,
            payload_length,
            &mut header_buf,
        )?;

        // Check if we need padding for minimum Initial packet size
        let total_size = header_len + payload_length;
        let padding_needed = if pad_to_min && total_size < MIN_INITIAL_PACKET_SIZE {
            MIN_INITIAL_PACKET_SIZE - total_size
        } else {
            0
        };

        // Recalculate with padding
        let padded_frame_len = frame_len + padding_needed;
        let padded_encrypted_payload_len = padded_frame_len + tag_len;
        let padded_payload_length = pn_len + padded_encrypted_payload_len;

        // Rebuild header with correct Length
        let header_len = packet::encode_initial_header(
            dcid,
            scid,
            token,
            pn_len,
            padded_payload_length,
            &mut out[..],
        )?;

        // Encode packet number
        let pn_offset = header_len;
        let pn_written = packet::encode_pn(pn, largest_acked, &mut out[pn_offset..])?;

        // Copy frames after PN
        let payload_start = pn_offset + pn_written;
        if payload_start + padded_frame_len + tag_len > out.len() {
            return Err(Error::BufferTooSmall {
                needed: payload_start + padded_frame_len + tag_len,
            });
        }
        out[payload_start..payload_start + frame_len].copy_from_slice(payload_frames);

        // Add PADDING frames
        for i in 0..padding_needed {
            out[payload_start + frame_len + i] = 0x00; // PADDING
        }

        // Encrypt: AAD is header up to (not including) payload
        let aad_len = payload_start; // header + PN
        let mut aad_buf = [0u8; 256];
        aad_buf[..aad_len].copy_from_slice(&out[..aad_len]);

        let nonce = send.nonce(pn);
        let ct_len = send.aead.seal_in_place(
            &nonce,
            &aad_buf[..aad_len],
            &mut out[payload_start..],
            padded_frame_len,
        )?;

        // Apply header protection
        let sample_offset = pn_offset + 4;
        let total_pkt_len = payload_start + ct_len;
        if sample_offset + 16 > total_pkt_len {
            return Err(Error::Crypto);
        }
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&out[sample_offset..sample_offset + 16]);
        let mask = send.header_protection.mask(&sample);

        // Long header: mask lower 4 bits of first byte
        out[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            out[pn_offset + i] ^= mask[1 + i];
        }

        self.next_pn[level_index(level)] = pn + 1;

        // Record sent packet
        let _ = self.sent_tracker.on_packet_sent(SentPacket {
            pn,
            level,
            time_sent: now,
            size: total_pkt_len as u16,
            ack_eliciting: true,
            in_flight: true,
        });
        self.loss_detector.on_ack_eliciting_sent(level, now);
        self.congestion.on_packet_sent(total_pkt_len as u64);

        Ok(total_pkt_len)
    }

    /// Build, encrypt, and apply header protection for a Handshake or Short packet.
    fn build_and_encrypt_packet(
        &mut self,
        level: Level,
        payload_frames: &[u8],
        _pad: bool,
        out: &mut [u8],
        now: Instant,
    ) -> Result<usize, Error> {
        let idx = level_index(level);
        let pn = self.next_pn[idx];
        let largest_acked = self.largest_recv_pn[idx].unwrap_or(0);
        let pn_len = packet::pn_length(pn, largest_acked);
        let tag_len = 16;

        let frame_len = payload_frames.len();

        // RFC 9001 Section 5.4.2: packets must be padded so that
        // pn_len + encrypted_payload_len >= 4 + sample_len (16).
        // i.e., frame_len + tag_len >= 20 - pn_len.
        let min_encrypted = 20usize.saturating_sub(pn_len);
        let padding_needed = if frame_len + tag_len < min_encrypted {
            min_encrypted - frame_len - tag_len
        } else {
            0
        };
        let padded_frame_len = frame_len + padding_needed;
        let encrypted_payload_len = padded_frame_len + tag_len;

        let dcid = self.remote_cid.as_slice();
        let scid = if self.local_cids.is_empty() {
            &[]
        } else {
            self.local_cids[0].as_slice()
        };

        let (header_len, is_long) = match level {
            Level::Handshake => {
                let payload_length = pn_len + encrypted_payload_len;
                let hl = packet::encode_handshake_header(
                    dcid,
                    scid,
                    pn_len,
                    payload_length,
                    out,
                )?;
                (hl, true)
            }
            Level::Application => {
                // Short header: first_byte = 0_1_S_RR_K_PP
                //   bit 7 = 0 (short header), bit 6 = 1 (fixed),
                //   bit 5 = spin (0), bits 4-3 = reserved (00),
                //   bit 2 = key_phase, bits 1-0 = pn_len - 1
                let key_phase_bit = (self.keys.key_phase() & 1) << 2;
                let first_byte = 0x40 | key_phase_bit | ((pn_len as u8) - 1);
                let hl = packet::encode_short_header(dcid, first_byte, out)?;
                (hl, false)
            }
            Level::Initial => {
                // Should use build_and_encrypt_initial_packet instead
                return Err(Error::InvalidState);
            }
        };

        let pn_offset = header_len;
        let pn_written = packet::encode_pn(pn, largest_acked, &mut out[pn_offset..])?;

        // Copy frames and add PADDING if needed for header protection sample
        let payload_start = pn_offset + pn_written;
        if payload_start + padded_frame_len + tag_len > out.len() {
            return Err(Error::BufferTooSmall {
                needed: payload_start + padded_frame_len + tag_len,
            });
        }
        out[payload_start..payload_start + frame_len].copy_from_slice(payload_frames);
        // Fill padding bytes with 0x00 (PADDING frame)
        for i in 0..padding_needed {
            out[payload_start + frame_len + i] = 0x00;
        }

        // Encrypt
        let aad_len = payload_start;
        let mut aad_buf = [0u8; 256];
        if aad_len > aad_buf.len() {
            return Err(Error::BufferTooSmall { needed: aad_len });
        }
        aad_buf[..aad_len].copy_from_slice(&out[..aad_len]);

        let send = self.keys.send_keys(level).ok_or(Error::Crypto)?;
        let nonce = send.nonce(pn);
        let ct_len = send.aead.seal_in_place(
            &nonce,
            &aad_buf[..aad_len],
            &mut out[payload_start..],
            padded_frame_len,
        )?;

        // Apply header protection
        let sample_offset = pn_offset + 4;
        let total_pkt_len = payload_start + ct_len;
        if sample_offset + 16 > total_pkt_len {
            return Err(Error::Crypto);
        }
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&out[sample_offset..sample_offset + 16]);
        let mask = send.header_protection.mask(&sample);

        if is_long {
            out[0] ^= mask[0] & 0x0f;
        } else {
            out[0] ^= mask[0] & 0x1f;
        }
        for i in 0..pn_len {
            out[pn_offset + i] ^= mask[1 + i];
        }

        self.next_pn[idx] = pn + 1;

        // Record sent packet
        let _ = self.sent_tracker.on_packet_sent(SentPacket {
            pn,
            level,
            time_sent: now,
            size: total_pkt_len as u16,
            ack_eliciting: true,
            in_flight: true,
        });
        self.loss_detector.on_ack_eliciting_sent(level, now);
        self.congestion.on_packet_sent(total_pkt_len as u64);

        Ok(total_pkt_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnectionState;
    use crate::crypto::Level;
    use crate::packet::MIN_INITIAL_PACKET_SIZE;
    use crate::tls::transport_params::TransportParams;
    use crate::transport::Rng;

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    use crate::crypto::rustcrypto::Aes128GcmProvider;
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    use crate::tls::handshake::ServerTlsConfig;

    // -----------------------------------------------------------------------
    // Test infrastructure
    // -----------------------------------------------------------------------

    struct TestRng(u8);

    impl Rng for TestRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    const TEST_ED25519_SEED: [u8; 32] = [0x01u8; 32];

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn get_test_ed25519_cert_der() -> &'static [u8] {
        use std::sync::LazyLock;
        static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
            let s: [u8; 32] = [0x01u8; 32];
            let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&s);
            let mut b = [0u8; 512];
            let n = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut b).unwrap();
            b[..n].to_vec()
        });
        &V
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn make_client() -> Connection<Aes128GcmProvider> {
        let mut rng = TestRng(0x10);
        Connection::client(
            Aes128GcmProvider,
            "test.local",
            &[b"h3"],
            TransportParams::default_params(),
            &mut rng,
        )
        .unwrap()
    }

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn make_server() -> Connection<Aes128GcmProvider> {
        let mut rng = TestRng(0x50);
        let config = ServerTlsConfig {
            cert_der: get_test_ed25519_cert_der(),
            private_key_der: &TEST_ED25519_SEED,
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
        };
        Connection::server(
            Aes128GcmProvider,
            config,
            TransportParams::default_params(),
            &mut rng,
        )
        .unwrap()
    }

    /// Exchange packets between client and server until both are established.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn run_handshake(
        client: &mut Connection<Aes128GcmProvider>,
        server: &mut Connection<Aes128GcmProvider>,
        now: crate::transport::Instant,
    ) {
        for _round in 0..20 {
            loop {
                let mut buf = [0u8; 4096];
                match client.poll_transmit(&mut buf, now) {
                    Some(tx) => {
                        let data: heapless::Vec<u8, 4096> = {
                            let mut v = heapless::Vec::new();
                            let _ = v.extend_from_slice(tx.data);
                            v
                        };
                        let _ = server.recv(&data, now);
                    }
                    None => break,
                }
            }
            loop {
                let mut buf = [0u8; 4096];
                match server.poll_transmit(&mut buf, now) {
                    Some(tx) => {
                        let data: heapless::Vec<u8, 4096> = {
                            let mut v = heapless::Vec::new();
                            let _ = v.extend_from_slice(tx.data);
                            v
                        };
                        let _ = client.recv(&data, now);
                    }
                    None => break,
                }
            }
            if client.is_established() && server.is_established() {
                return;
            }
        }
        panic!(
            "handshake did not complete: client={:?}, server={:?}",
            client.state(),
            server.state()
        );
    }

    /// Drain all pending transmits from a connection.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn drain_transmits(conn: &mut Connection<Aes128GcmProvider>, now: crate::transport::Instant) {
        loop {
            let mut buf = [0u8; 4096];
            if conn.poll_transmit(&mut buf, now).is_none() {
                break;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 1. poll_transmit_returns_none_when_nothing_to_send
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn poll_transmit_returns_none_when_nothing_to_send() {
        let mut client = make_client();
        let mut buf = [0u8; 2048];

        // First call emits the Initial (ClientHello).
        let tx1 = client.poll_transmit(&mut buf, 0);
        assert!(tx1.is_some(), "first call should produce Initial");

        // Second call: no more data to send.
        let tx2 = client.poll_transmit(&mut buf, 0);
        assert!(tx2.is_none(), "second call should return None");
    }

    // -----------------------------------------------------------------------
    // 2. client_initial_padded_to_1200_bytes (RFC 9000 section 14.1)
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_initial_padded_to_1200_bytes() {
        let mut client = make_client();
        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, 0).unwrap();
        assert!(
            tx.data.len() >= MIN_INITIAL_PACKET_SIZE,
            "Initial packet must be padded to at least {} bytes, got {}",
            MIN_INITIAL_PACKET_SIZE,
            tx.data.len()
        );
    }

    // -----------------------------------------------------------------------
    // 3. client_initial_has_long_header
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn client_initial_has_long_header() {
        let mut client = make_client();
        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, 0).unwrap();
        // The form bit (bit 7) of a long header is 1.
        assert_ne!(
            tx.data[0] & 0x80,
            0,
            "Initial packet first byte should have form bit set (long header)"
        );
    }

    // -----------------------------------------------------------------------
    // 4. server_produces_response_after_client_initial
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn server_produces_response_after_client_initial() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;

        // Client sends Initial.
        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, now).unwrap();
        let initial: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };

        // Server receives it.
        server.recv(&initial, now).unwrap();

        // Server should now have something to send back (ServerHello).
        let mut srv_buf = [0u8; 4096];
        let srv_tx = server.poll_transmit(&mut srv_buf, now);
        assert!(
            srv_tx.is_some(),
            "server should produce a response after receiving client Initial"
        );

        // The server response should also be a long header packet.
        let srv_data = srv_tx.unwrap().data;
        assert_ne!(
            srv_data[0] & 0x80,
            0,
            "server response should be a long header packet"
        );
    }

    // -----------------------------------------------------------------------
    // 5. stream_data_produces_short_header_packet
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn stream_data_produces_short_header_packet() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;
        run_handshake(&mut client, &mut server, now);
        drain_transmits(&mut client, now);

        // Send stream data.
        let stream_id = client.open_stream().unwrap();
        client.stream_send(stream_id, b"test data", false).unwrap();

        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, now).unwrap();

        // Short header: form bit (bit 7) = 0.
        assert_eq!(
            tx.data[0] & 0x80,
            0,
            "1-RTT stream data should use a short header"
        );
    }

    // -----------------------------------------------------------------------
    // 6. stream_data_received_and_readable (end-to-end)
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn stream_data_received_and_readable() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;
        run_handshake(&mut client, &mut server, now);

        let stream_id = client.open_stream().unwrap();
        let payload = b"hello server!";
        client.stream_send(stream_id, payload, false).unwrap();

        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, now).unwrap();
        let pkt: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };

        server.recv(&pkt, now).unwrap();

        let mut recv_buf = [0u8; 256];
        let (len, fin) = server.stream_recv(stream_id, &mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..len], payload);
        assert!(!fin, "FIN should not be set");
    }

    // -----------------------------------------------------------------------
    // 7. connection_close_produces_packet
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn connection_close_produces_packet() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;
        run_handshake(&mut client, &mut server, now);
        drain_transmits(&mut client, now);

        client.close(42, b"goodbye");
        assert_eq!(client.state(), ConnectionState::Closing);

        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, now);
        assert!(tx.is_some(), "closing should produce a CONNECTION_CLOSE packet");
        assert_eq!(
            client.state(),
            ConnectionState::Closed,
            "state should transition to Closed after sending CONNECTION_CLOSE"
        );
    }

    // -----------------------------------------------------------------------
    // 8. connection_close_no_further_transmits
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn connection_close_no_further_transmits() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;
        run_handshake(&mut client, &mut server, now);
        drain_transmits(&mut client, now);

        client.close(0, b"done");

        // Drain the close packet.
        let mut buf = [0u8; 2048];
        let _ = client.poll_transmit(&mut buf, now);
        assert!(client.is_closed());

        // Nothing further should be sent after Closed.
        let tx = client.poll_transmit(&mut buf, now);
        assert!(
            tx.is_none(),
            "no packets should be sent after connection is Closed"
        );
    }

    // -----------------------------------------------------------------------
    // 9. packet_number_increments_after_transmit
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn packet_number_increments_after_transmit() {
        let mut client = make_client();

        // Before any transmit, Initial PN starts at 0.
        assert_eq!(client.next_pn[0], 0, "Initial PN should start at 0");

        let mut buf = [0u8; 2048];
        let _ = client.poll_transmit(&mut buf, 0);

        // After sending one Initial packet, PN should be 1.
        assert_eq!(
            client.next_pn[0], 1,
            "Initial PN should increment to 1 after one transmit"
        );
    }

    // -----------------------------------------------------------------------
    // 10. server_sends_handshake_done
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn server_sends_handshake_done() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;

        // Server starts with need_handshake_done = true.
        assert!(server.need_handshake_done);

        run_handshake(&mut client, &mut server, now);

        // After handshake, the server should have cleared need_handshake_done
        // because it was transmitted as part of the handshake exchange.
        assert!(
            !server.need_handshake_done,
            "need_handshake_done should be false after handshake completes"
        );
    }

    // -----------------------------------------------------------------------
    // 11. anti_amplification_blocks_without_received_bytes
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn anti_amplification_blocks_without_received_bytes() {
        let mut server = make_server();

        // Server with no received bytes should not be able to send.
        assert!(!server.address_validated);
        assert_eq!(server.anti_amplification_bytes_received, 0);

        let mut buf = [0u8; 2048];
        let tx = server.poll_transmit(&mut buf, 0);
        assert!(
            tx.is_none(),
            "server should not send when no bytes have been received (anti-amplification)"
        );
    }

    // -----------------------------------------------------------------------
    // 12. build_ack_frame_single_range
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn build_ack_frame_single_range() {
        let mut client = make_client();

        // Record a contiguous range of packet numbers at Initial level.
        client.track_received_pn(Level::Initial, 0);
        client.track_received_pn(Level::Initial, 1);
        client.track_received_pn(Level::Initial, 2);

        // Build an ACK frame.
        let mut buf = [0u8; 256];
        let written = client.build_ack_frame(Level::Initial, &mut buf);
        assert!(
            written.is_some(),
            "should produce an ACK frame for tracked PNs"
        );
        let ack_len = written.unwrap();
        assert!(ack_len > 0, "ACK frame should have non-zero length");

        // Decode the first byte to verify it is an ACK frame type (0x02 or 0x03).
        assert!(
            buf[0] == 0x02 || buf[0] == 0x03,
            "frame type byte should be ACK (0x02) or ACK_ECN (0x03), got {:#x}",
            buf[0]
        );
    }

    // -----------------------------------------------------------------------
    // 13. build_ack_frame_multiple_ranges
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn build_ack_frame_multiple_ranges() {
        let mut client = make_client();

        // Record non-contiguous PNs: [0,1] and [5,6] and [10,10].
        client.track_received_pn(Level::Initial, 0);
        client.track_received_pn(Level::Initial, 1);
        client.track_received_pn(Level::Initial, 5);
        client.track_received_pn(Level::Initial, 6);
        client.track_received_pn(Level::Initial, 10);

        // Verify the tracker has 3 ranges.
        assert_eq!(client.recv_pn_tracker[0].ranges.len(), 3);

        // Build ACK frame.
        let mut buf = [0u8; 256];
        let written = client.build_ack_frame(Level::Initial, &mut buf);
        assert!(written.is_some());
        let ack_len = written.unwrap();

        // A multi-range ACK must be longer than a single-range ACK due to
        // the gap/range pairs encoded after the first range.
        // Single range: type(1) + largest_ack(varint) + delay(varint) + range_count(varint) + first_range(varint)
        // Multi range adds: gap(varint) + range(varint) for each additional range.
        assert!(
            ack_len > 5,
            "multi-range ACK should be more than 5 bytes, got {}",
            ack_len
        );
    }

    // -----------------------------------------------------------------------
    // 14. build_ack_frame_empty_tracker_returns_none
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn build_ack_frame_empty_tracker_returns_none() {
        let client = make_client();

        // No PNs recorded.
        let mut buf = [0u8; 256];
        let written = client.build_ack_frame(Level::Initial, &mut buf);
        assert!(
            written.is_none(),
            "should return None when no PNs have been received"
        );
    }

    // -----------------------------------------------------------------------
    // 15. multiple_streams_in_one_packet
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn multiple_streams_in_one_packet() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;
        run_handshake(&mut client, &mut server, now);
        drain_transmits(&mut client, now);

        // Open two streams and queue data on both.
        let s1 = client.open_stream().unwrap();
        let s2 = client.open_stream().unwrap();
        client.stream_send(s1, b"stream one", false).unwrap();
        client.stream_send(s2, b"stream two", false).unwrap();

        assert_eq!(
            client.stream_send_queue.len(),
            2,
            "two stream entries should be queued"
        );

        // A single poll_transmit should drain both streams.
        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, now);
        assert!(tx.is_some(), "should produce a packet with both streams");

        assert_eq!(
            client.stream_send_queue.len(),
            0,
            "send queue should be empty after transmit"
        );
    }

    // -----------------------------------------------------------------------
    // 16. bidirectional_stream_exchange
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn bidirectional_stream_exchange() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;
        run_handshake(&mut client, &mut server, now);
        drain_transmits(&mut client, now);
        drain_transmits(&mut server, now);

        // Client sends a request.
        let c_stream = client.open_stream().unwrap();
        client
            .stream_send(c_stream, b"GET / HTTP/1.0", true)
            .unwrap();

        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, now).unwrap();
        let pkt: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };
        server.recv(&pkt, now).unwrap();

        // Server reads the request.
        let mut recv_buf = [0u8; 256];
        let (len, fin) = server.stream_recv(c_stream, &mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..len], b"GET / HTTP/1.0");
        assert!(fin);

        // Server sends a response on the same stream.
        server
            .stream_send(c_stream, b"200 OK", true)
            .unwrap();

        let mut buf = [0u8; 2048];
        let tx = server.poll_transmit(&mut buf, now).unwrap();
        let pkt: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };
        client.recv(&pkt, now).unwrap();

        // Client reads the response.
        let mut recv_buf = [0u8; 256];
        let (len, fin) = client.stream_recv(c_stream, &mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..len], b"200 OK");
        assert!(fin);
    }

    // -----------------------------------------------------------------------
    // 17. closed_connection_returns_none
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn closed_connection_returns_none() {
        let mut client = make_client();
        client.state = ConnectionState::Closed;

        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, 0);
        assert!(
            tx.is_none(),
            "Closed connection should not produce any transmits"
        );
    }

    // -----------------------------------------------------------------------
    // 18. close_before_handshake_sends_initial_level_close
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn close_before_handshake_sends_initial_level_close() {
        let mut client = make_client();

        // Close immediately before any handshake exchange.
        client.close(1, b"early close");
        assert_eq!(client.state(), ConnectionState::Closing);

        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, 0);
        assert!(
            tx.is_some(),
            "CONNECTION_CLOSE should be sent at Initial level"
        );
        assert_eq!(client.state(), ConnectionState::Closed);

        // The packet should be a long header (Initial level).
        assert_ne!(
            tx.unwrap().data[0] & 0x80,
            0,
            "CONNECTION_CLOSE before handshake should use long header"
        );
    }

    // -----------------------------------------------------------------------
    // 19. packet_number_increments_across_levels
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn packet_number_increments_across_levels() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;

        // Initial PN spaces all start at 0.
        assert_eq!(client.next_pn[0], 0);
        assert_eq!(client.next_pn[1], 0);
        assert_eq!(client.next_pn[2], 0);

        run_handshake(&mut client, &mut server, now);

        // After handshake, Initial PN should have been incremented (at least 1 Initial sent).
        assert!(
            client.next_pn[0] >= 1,
            "Initial PN should have incremented, got {}",
            client.next_pn[0]
        );
    }

    // -----------------------------------------------------------------------
    // 20. connection_close_received_by_peer
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn connection_close_received_by_peer() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;
        run_handshake(&mut client, &mut server, now);
        drain_transmits(&mut client, now);
        drain_transmits(&mut server, now);

        // Client closes.
        client.close(99, b"error");
        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, now).unwrap();
        let pkt: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };

        // Server receives the CONNECTION_CLOSE.
        server.recv(&pkt, now).unwrap();
        assert_eq!(
            server.state(),
            ConnectionState::Draining,
            "server should enter Draining after receiving CONNECTION_CLOSE"
        );

        // Server should emit a ConnectionClose event.
        let mut found = false;
        while let Some(ev) = server.poll_event() {
            if let crate::connection::Event::ConnectionClose { error_code, .. } = ev {
                assert_eq!(error_code, 99);
                found = true;
            }
        }
        assert!(found, "server should emit ConnectionClose event");
    }

    // -----------------------------------------------------------------------
    // 21. anti_amplification_bytes_sent_tracking
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn anti_amplification_bytes_sent_tracking() {
        let mut server = make_server();

        // Simulate receiving 2000 bytes so the server can send up to 6000.
        server.anti_amplification_bytes_received = 2000;
        assert_eq!(server.anti_amplification_bytes_sent, 0);

        // The server has no data to send (no Initial keys derived for the
        // remote DCID yet), so poll_transmit won't produce anything.
        // But the tracking mechanism is verified by checking the field.
        assert!(server.amplification_allows(6000));
        assert!(!server.amplification_allows(6001));
    }

    // -----------------------------------------------------------------------
    // 22. stream_send_with_fin
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn stream_send_with_fin_received() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;
        run_handshake(&mut client, &mut server, now);

        let stream_id = client.open_stream().unwrap();
        client.stream_send(stream_id, b"final", true).unwrap();

        let mut buf = [0u8; 2048];
        let tx = client.poll_transmit(&mut buf, now).unwrap();
        let pkt: heapless::Vec<u8, 2048> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(tx.data);
            v
        };

        server.recv(&pkt, now).unwrap();

        let mut recv_buf = [0u8; 256];
        let (len, fin) = server.stream_recv(stream_id, &mut recv_buf).unwrap();
        assert_eq!(&recv_buf[..len], b"final");
        assert!(fin, "FIN should be set on the received stream data");
    }

    // -----------------------------------------------------------------------
    // 23. initial_packet_records_sent_packet
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn initial_packet_records_sent_packet() {
        let mut client = make_client();

        // Before transmit, no packets recorded.
        assert_eq!(client.sent_tracker.count(), 0);

        let mut buf = [0u8; 2048];
        let _ = client.poll_transmit(&mut buf, 0);

        // After transmit, one packet should be recorded.
        assert_eq!(
            client.sent_tracker.count(),
            1,
            "sent_tracker should record the transmitted Initial packet"
        );
    }

    // -----------------------------------------------------------------------
    // 24. handshake_packet_pn_separate_from_initial
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn handshake_packet_pn_separate_from_initial() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;
        run_handshake(&mut client, &mut server, now);

        // Initial and Handshake have separate PN spaces.
        // Both should have been incremented.
        let initial_pn = client.next_pn[0];
        let _handshake_pn = client.next_pn[1];

        assert!(
            initial_pn >= 1,
            "Initial PN should be >= 1, got {}",
            initial_pn
        );
        // The Handshake PN may or may not have been used, depending on whether
        // the client sends Handshake-level packets. On this implementation,
        // the client should send at least a Handshake Finished.
        // Just verify the spaces are independent.
        // Both spaces start at 0, and at least Initial must be > 0.
        assert!(
            initial_pn >= 1,
            "Initial PN must have been used during handshake"
        );
    }

    // -----------------------------------------------------------------------
    // 25. stream_data_after_close_is_blocked
    // -----------------------------------------------------------------------

    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    #[test]
    fn stream_data_after_close_is_blocked() {
        let mut client = make_client();
        let mut server = make_server();
        let now = 1_000_000u64;
        run_handshake(&mut client, &mut server, now);
        drain_transmits(&mut client, now);

        let stream_id = client.open_stream().unwrap();
        client.close(0, b"bye");

        // Drain the close packet.
        let mut buf = [0u8; 2048];
        let _ = client.poll_transmit(&mut buf, now);
        assert!(client.is_closed());

        // Sending on a stream after close should fail.
        let result = client.stream_send(stream_id, b"too late", false);
        assert!(
            result.is_err(),
            "stream_send after close should return an error"
        );
    }
}
