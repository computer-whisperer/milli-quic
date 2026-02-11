//! Transmit path: build frames, encrypt packets, emit datagrams.

use crate::crypto::{Aead, CryptoProvider, HeaderProtection, Level};
use crate::error::Error;
use crate::frame::{self, AckFrame, ConnectionCloseFrame, CryptoFrame, Frame, StreamFrame};
use crate::packet::{self, MIN_INITIAL_PACKET_SIZE};
use crate::tls::TlsSession;
use crate::transport::Instant;
use crate::transport::recovery::SentPacket;

use super::recv::level_index;
use super::{Connection, ConnectionConfig, ConnectionState, Transmit};

impl<C: CryptoProvider, Cfg: ConnectionConfig> Connection<C, Cfg>
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
                reason: &reason,
            });
            if let Ok(frame_len) = frame::encode(&close_frame, &mut frame_buf) {
                let result = if level == Level::Initial {
                    let is_client = self.role == crate::tls::handshake::Role::Client;
                    self.build_and_encrypt_initial_packet(
                        &frame_buf[..frame_len],
                        is_client,
                        buf,
                        now,
                    )
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
        if self.keys.has_send_keys(Level::Initial) {
            if let Some(pkt_len) = self.build_initial_packet(&mut buf[total_written..], now) {
                total_written += pkt_len;
            }
        }

        // 3. Handshake-level data (TLS handshake messages in CRYPTO frames, ACKs)
        if self.keys.has_send_keys(Level::Handshake) {
            if let Some(pkt_len) = self.build_handshake_packet(&mut buf[total_written..], now) {
                total_written += pkt_len;
            }
        }

        // 4. Application-level data (STREAM frames, ACKs, HANDSHAKE_DONE, etc.)
        if self.keys.has_send_keys(Level::Application) {
            if let Some(pkt_len) = self.build_short_packet(&mut buf[total_written..], now) {
                total_written += pkt_len;
            }
        }

        if total_written > 0 {
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
        if self.ack_eliciting_received[level_index(level)] {
            if let Some(written) = self.build_ack_frame(level, &mut frame_buf[frame_len..]) {
                frame_len += written;
                self.ack_eliciting_received[level_index(level)] = false;
            }
        }

        // CRYPTO frame from TLS engine
        let crypto_written = self.write_tls_crypto_data(level, &mut frame_buf[frame_len..]);
        frame_len += crypto_written;

        if frame_len == 0 {
            return None;
        }

        // Pad Initial packets from client to 1200 bytes minimum
        let is_client = self.role == crate::tls::handshake::Role::Client;

        match self.build_and_encrypt_initial_packet(
            &frame_buf[..frame_len],
            is_client,
            buf,
            now,
        ) {
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
        if self.ack_eliciting_received[level_index(level)] {
            if let Some(written) = self.build_ack_frame(level, &mut frame_buf[frame_len..]) {
                frame_len += written;
                self.ack_eliciting_received[level_index(level)] = false;
            }
        }

        // CRYPTO frame from TLS engine
        let crypto_written = self.write_tls_crypto_data(level, &mut frame_buf[frame_len..]);
        frame_len += crypto_written;

        if frame_len == 0 {
            return None;
        }

        match self.build_and_encrypt_packet(level, &frame_buf[..frame_len], false, buf, now) {
            Ok(pkt_len) => Some(pkt_len),
            Err(_) => None,
        }
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
        if self.role == crate::tls::handshake::Role::Server && self.need_handshake_done {
            if let Ok(written) = frame::encode(&Frame::HandshakeDone, &mut frame_buf[frame_len..]) {
                frame_len += written;
                sending_handshake_done = true;
            }
        }

        // ACK frame if needed
        if self.ack_eliciting_received[level_index(level)] {
            if let Some(written) = self.build_ack_frame(level, &mut frame_buf[frame_len..]) {
                frame_len += written;
                self.ack_eliciting_received[level_index(level)] = false;
            }
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
    fn build_ack_frame(&self, level: Level, buf: &mut [u8]) -> Option<usize> {
        let idx = level_index(level);
        let largest = self.largest_recv_pn[idx]?;

        // Simple ACK: acknowledge everything from 0 to largest_recv_pn
        // (This is a simplification; a full implementation would track ranges.)
        let ack = Frame::Ack(AckFrame {
            largest_ack: largest,
            ack_delay: 0,
            first_ack_range: largest, // ack all from 0 to largest
            ack_ranges: &[],
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
    fn build_and_encrypt_initial_packet(
        &mut self,
        payload_frames: &[u8],
        pad_to_min: bool,
        out: &mut [u8],
        now: Instant,
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
                // Short header: first_byte = 0100_00xx where xx = pn_len - 1
                let first_byte = 0x40 | ((pn_len as u8) - 1);
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
