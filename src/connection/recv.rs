//! Receive path: decrypt incoming packets and dispatch frames.

use crate::crypto::{Aead, CryptoProvider, HeaderProtection, Level};
use crate::error::Error;
use crate::frame::{self, AckRangeIter, Frame};
use crate::packet::{self, CoalescedPackets};
use crate::tls::TlsSession;
use crate::transport::Instant;

use super::{Connection, ConnectionConfig, ConnectionState, Event};

/// Result of processing a single decrypted packet.
struct PacketResult {
    ack_eliciting: bool,
    level: Level,
    pn: u64,
}

impl<C: CryptoProvider, Cfg: ConnectionConfig> Connection<C, Cfg>
where
    C::Hkdf: Default,
{
    /// Process an incoming UDP datagram. May contain coalesced packets.
    pub fn recv(&mut self, datagram: &[u8], now: Instant) -> Result<(), Error> {
        if matches!(self.state, ConnectionState::Closed) {
            return Err(Error::Closed);
        }

        self.last_activity = now;

        // Anti-amplification: track bytes received (RFC 9000 section 8.1)
        if !self.address_validated {
            self.anti_amplification_bytes_received =
                self.anti_amplification_bytes_received.saturating_add(datagram.len());
        }

        // Iterate over coalesced packets in the datagram.
        let mut iter = CoalescedPackets::new(datagram);
        while let Some(pkt_result) = iter.next() {
            let pkt_data = match pkt_result {
                Ok(data) => data,
                Err(_) => break, // malformed coalescing, stop
            };

            if pkt_data.is_empty() {
                continue;
            }

            let first_byte = pkt_data[0];
            let is_long = first_byte & 0x80 != 0;

            let result = if is_long {
                let pkt_type = (first_byte & 0x30) >> 4;
                match pkt_type {
                    0b00 => self.recv_initial(pkt_data, now),
                    0b10 => self.recv_handshake(pkt_data, now),
                    _ => {
                        // 0-RTT, Retry, Version Negotiation: skip for now
                        continue;
                    }
                }
            } else {
                self.recv_short(pkt_data, now)
            };

            match result {
                Ok(pr) => {
                    if pr.ack_eliciting {
                        let idx = level_index(pr.level);
                        self.ack_eliciting_received[idx] = true;
                    }
                    // Update largest received PN for this space
                    let idx = level_index(pr.level);
                    match self.largest_recv_pn[idx] {
                        None => self.largest_recv_pn[idx] = Some(pr.pn),
                        Some(prev) if pr.pn > prev => {
                            self.largest_recv_pn[idx] = Some(pr.pn);
                        }
                        _ => {}
                    }
                    // Track received PNs for ACK generation
                    self.track_received_pn(pr.level, pr.pn);
                }
                Err(_) => {
                    // Decryption failure or parse error: silently discard this packet
                    // per RFC 9000 Section 12.2
                    continue;
                }
            }
        }

        // After processing, check for TLS-derived keys
        self.check_tls_keys()?;

        Ok(())
    }

    /// Process an Initial packet.
    fn recv_initial(&mut self, pkt_data: &[u8], now: Instant) -> Result<PacketResult, Error> {
        let (hdr, _consumed) = packet::parse_initial_header(pkt_data)?;

        // If we are server and this is the first Initial, derive Initial keys from DCID
        #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
        if !self.keys.has_recv_keys(Level::Initial) {
            // Server receiving first client Initial
            self.keys
                .derive_initial(&self.crypto, hdr.dcid, self.role == crate::tls::handshake::Role::Client)?;
        }

        // Store remote SCID if we haven't yet (server learns client SCID from Initial)
        if self.remote_cid.len == 0 && !hdr.scid.is_empty() {
            self.remote_cid = ConnectionId::from_slice(hdr.scid);
        }

        self.decrypt_and_process_long(pkt_data, &hdr.pn_offset, hdr.payload_length, Level::Initial, now)
    }

    /// Process a Handshake packet.
    fn recv_handshake(&mut self, pkt_data: &[u8], now: Instant) -> Result<PacketResult, Error> {
        let (hdr, _consumed) = packet::parse_handshake_header(pkt_data)?;

        self.decrypt_and_process_long(pkt_data, &hdr.pn_offset, hdr.payload_length, Level::Handshake, now)
    }

    /// Process a short (1-RTT) packet.
    fn recv_short(&mut self, pkt_data: &[u8], now: Instant) -> Result<PacketResult, Error> {
        let dcid_len = if self.local_cids.is_empty() {
            0
        } else {
            self.local_cids[0].len as usize
        };

        let (_hdr, hdr_len) = packet::parse_short_header(pkt_data, dcid_len)?;

        // For short header, pn_offset = hdr_len (1 + dcid_len)
        let pn_offset = hdr_len;

        // Need recv keys for Application level
        let recv = self.keys.recv_keys(Level::Application).ok_or(Error::Crypto)?;

        // We need to work on a mutable copy for decryption
        let mut buf = [0u8; 2048];
        let pkt_len = pkt_data.len();
        if pkt_len > buf.len() {
            return Err(Error::BufferTooSmall { needed: pkt_len });
        }
        buf[..pkt_len].copy_from_slice(pkt_data);

        // Remove header protection
        let sample_offset = pn_offset + 4;
        if sample_offset + 16 > pkt_len {
            return Err(Error::Crypto);
        }
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&buf[sample_offset..sample_offset + 16]);
        let mask = recv.header_protection.mask(&sample);

        // For short headers: first_byte ^= mask[0] & 0x1f
        buf[0] ^= mask[0] & 0x1f;
        let pn_len = ((buf[0] & 0x03) + 1) as usize;

        // Unmask PN bytes
        for i in 0..pn_len {
            buf[pn_offset + i] ^= mask[1 + i];
        }

        // Decode packet number
        let mut truncated_pn: u32 = 0;
        for i in 0..pn_len {
            truncated_pn = (truncated_pn << 8) | buf[pn_offset + i] as u32;
        }
        let largest_pn = self.largest_recv_pn[level_index(Level::Application)].unwrap_or(0);
        let pn = packet::decode_pn(truncated_pn, pn_len, largest_pn);

        // Reject unreasonably large packet numbers (> 2^62)
        if pn > crate::varint::MAX_VARINT {
            return Err(Error::Transport(crate::error::TransportError::ProtocolViolation));
        }

        // Decrypt payload
        let payload_offset = pn_offset + pn_len;
        let payload_len = pkt_len - payload_offset;

        let aad = &buf[..payload_offset]; // header up to and including PN is the AAD
        // We need a temporary copy of AAD since the buf will be mutated
        let mut aad_buf = [0u8; 128];
        if payload_offset > aad_buf.len() {
            return Err(Error::BufferTooSmall {
                needed: payload_offset,
            });
        }
        aad_buf[..payload_offset].copy_from_slice(aad);

        let nonce = recv.nonce(pn);
        let pt_len = recv.aead.open_in_place(
            &nonce,
            &aad_buf[..payload_offset],
            &mut buf[payload_offset..],
            payload_len,
        )?;

        // Parse and dispatch frames
        let ack_eliciting = self.dispatch_frames(&buf[payload_offset..payload_offset + pt_len], Level::Application, now)?;

        Ok(PacketResult {
            ack_eliciting,
            level: Level::Application,
            pn,
        })
    }

    /// Decrypt and process a long header packet (Initial or Handshake).
    fn decrypt_and_process_long(
        &mut self,
        pkt_data: &[u8],
        pn_offset: &usize,
        payload_length: usize,
        level: Level,
        now: Instant,
    ) -> Result<PacketResult, Error> {
        let pn_offset = *pn_offset;

        let recv = self.keys.recv_keys(level).ok_or(Error::Crypto)?;

        // Copy packet data to mutable buffer for in-place decryption
        let total_len = pn_offset + payload_length;
        let mut buf = [0u8; 2048];
        if total_len > buf.len() {
            return Err(Error::BufferTooSmall { needed: total_len });
        }
        buf[..total_len].copy_from_slice(&pkt_data[..total_len]);

        // Remove header protection (RFC 9001 Section 5.4.2)
        // Sample starts at pn_offset + 4
        let sample_offset = pn_offset + 4;
        if sample_offset + 16 > total_len {
            return Err(Error::Crypto);
        }
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&buf[sample_offset..sample_offset + 16]);
        let mask = recv.header_protection.mask(&sample);

        // For long headers: first_byte ^= mask[0] & 0x0f
        buf[0] ^= mask[0] & 0x0f;
        let pn_len = ((buf[0] & 0x03) + 1) as usize;

        // Unmask PN bytes
        for i in 0..pn_len {
            buf[pn_offset + i] ^= mask[1 + i];
        }

        // Decode packet number
        let mut truncated_pn: u32 = 0;
        for i in 0..pn_len {
            truncated_pn = (truncated_pn << 8) | buf[pn_offset + i] as u32;
        }
        let largest_pn = self.largest_recv_pn[level_index(level)].unwrap_or(0);
        let pn = packet::decode_pn(truncated_pn, pn_len, largest_pn);

        // Reject unreasonably large packet numbers (> 2^62)
        if pn > crate::varint::MAX_VARINT {
            return Err(Error::Transport(crate::error::TransportError::ProtocolViolation));
        }

        // Decrypt payload
        let payload_offset = pn_offset + pn_len;
        let encrypted_len = payload_length - pn_len; // payload_length includes PN

        // AAD is the entire header up to and including PN
        let mut aad_buf = [0u8; 256];
        if payload_offset > aad_buf.len() {
            return Err(Error::BufferTooSmall {
                needed: payload_offset,
            });
        }
        aad_buf[..payload_offset].copy_from_slice(&buf[..payload_offset]);

        let nonce = recv.nonce(pn);
        let pt_len = recv.aead.open_in_place(
            &nonce,
            &aad_buf[..payload_offset],
            &mut buf[payload_offset..],
            encrypted_len,
        )?;

        // Parse and dispatch frames
        let ack_eliciting = self.dispatch_frames(&buf[payload_offset..payload_offset + pt_len], level, now)?;

        Ok(PacketResult {
            ack_eliciting,
            level,
            pn,
        })
    }

    /// Parse and dispatch all frames from decrypted payload.
    /// Returns true if any frame was ack-eliciting.
    fn dispatch_frames(
        &mut self,
        payload: &[u8],
        level: Level,
        now: Instant,
    ) -> Result<bool, Error> {
        let mut ack_eliciting = false;
        let mut pos = 0;

        while pos < payload.len() {
            let (frame, consumed) = frame::decode(&payload[pos..])?;
            pos += consumed;

            // All frames except PADDING and ACK are ack-eliciting
            match &frame {
                Frame::Padding | Frame::Ack(_) => {}
                _ => {
                    ack_eliciting = true;
                }
            }

            self.dispatch_frame(frame, level, now)?;
        }

        Ok(ack_eliciting)
    }

    /// Dispatch a single frame.
    fn dispatch_frame(
        &mut self,
        frame: Frame<'_>,
        level: Level,
        now: Instant,
    ) -> Result<(), Error> {
        match frame {
            Frame::Padding => {}

            Frame::Ping => {
                // Ack-eliciting, nothing else to do
            }

            Frame::Ack(ack) => {
                // Parse additional ranges
                let mut ranges: heapless::Vec<(u64, u64), 16> = heapless::Vec::new();
                let iter = AckRangeIter::new(ack.ack_ranges);
                for range_result in iter {
                    let (gap, ack_range) = range_result?;
                    let _ = ranges.push((gap, ack_range));
                }

                // Process ACK through the sent packet tracker
                let ack_result = self.sent_tracker.on_ack_received(
                    level,
                    ack.largest_ack,
                    ack.first_ack_range,
                    &ranges,
                );

                // Update loss detector
                self.loss_detector.on_ack_received(level, ack.largest_ack);

                // Update RTT if we have a newly acked packet
                if let Some(largest) = ack_result.largest_newly_acked {
                    if largest.time_sent > 0 && now >= largest.time_sent {
                        let latest_rtt = now - largest.time_sent;
                        let ack_delay = ack.ack_delay; // in microseconds (simplified)
                        let handshake_confirmed =
                            matches!(self.state, ConnectionState::Active);
                        self.loss_detector
                            .update_rtt(latest_rtt, ack_delay, handshake_confirmed);
                    }
                    self.loss_detector.reset_pto_count();
                }

                // Update congestion controller for acked packets
                for pkt in &ack_result.newly_acked {
                    self.congestion
                        .on_packet_acked(pkt.size as u64, pkt.time_sent, now);
                }

                // Detect lost packets
                let (lost_pns, _loss_timer) =
                    self.loss_detector
                        .detect_lost_packets(level, &self.sent_tracker, now);
                for lost_pn in &lost_pns {
                    if let Some(lost) = self.sent_tracker.remove(level, *lost_pn) {
                        self.congestion
                            .on_packet_lost(lost.size as u64, lost.time_sent, now);
                    }
                }
            }

            Frame::Crypto(crypto) => {
                self.handle_crypto_frame(level, crypto.offset, crypto.data)?;
            }

            Frame::Stream(stream) => {
                let is_client = self.role == crate::tls::handshake::Role::Client;

                // Get or create the stream
                let initial_max = self.local_params.initial_max_stream_data_bidi_remote;
                let _stream_state = self
                    .streams
                    .get_or_create(stream.stream_id, is_client, initial_max);

                // Even if get_or_create fails (e.g., capacity), try to mark received
                if self.streams.get(stream.stream_id).is_some() {
                    let _ = self.streams.mark_recv(
                        stream.stream_id,
                        stream.offset,
                        stream.data.len() as u64,
                        stream.fin,
                    );

                    // Store the stream data in our receive buffer
                    self.store_stream_data(stream.stream_id, stream.offset, stream.data, stream.fin);

                    // Generate event
                    let _ = self.events.push_back(Event::StreamReadable(stream.stream_id));
                }
            }

            Frame::MaxData(max_data) => {
                self.flow_control.handle_max_data(max_data);
            }

            Frame::MaxStreamData(msd) => {
                let _ = self
                    .streams
                    .handle_max_stream_data(msd.stream_id, msd.max_data);
            }

            Frame::MaxStreams(ms) => {
                self.flow_control
                    .handle_max_streams(ms.bidirectional, ms.max_streams);
            }

            Frame::ResetStream(rst) => {
                if self.streams.get(rst.stream_id).is_some() {
                    let _ = self.streams.handle_reset(rst.stream_id, rst.final_size);
                    let _ = self.events.push_back(Event::StreamReset {
                        stream_id: rst.stream_id,
                        error_code: rst.error_code,
                    });
                }
            }

            Frame::StopSending(ss) => {
                if self.streams.get(ss.stream_id).is_some() {
                    let _ = self.streams.handle_stop_sending(ss.stream_id);
                    let _ = self.events.push_back(Event::StopSending {
                        stream_id: ss.stream_id,
                        error_code: ss.error_code,
                    });
                }
            }

            Frame::ConnectionClose(cc) => {
                self.state = ConnectionState::Draining;
                let mut reason = heapless::Vec::new();
                let copy_len = cc.reason.len().min(64);
                let _ = reason.extend_from_slice(&cc.reason[..copy_len]);
                let _ = self.events.push_back(Event::ConnectionClose {
                    error_code: cc.error_code,
                    reason,
                });
            }

            Frame::HandshakeDone => {
                // Only meaningful client-side: server sent HANDSHAKE_DONE
                if self.role == crate::tls::handshake::Role::Client {
                    if matches!(self.state, ConnectionState::Handshaking) {
                        self.state = ConnectionState::Active;
                        self.address_validated = true;
                        let _ = self.events.push_back(Event::Connected);
                    }
                    // Drop handshake keys now that handshake is confirmed
                    self.keys.drop_handshake();
                    self.sent_tracker.drop_space(Level::Handshake);
                    self.loss_detector.drop_space(Level::Handshake);
                }
            }

            Frame::NewToken(_) | Frame::NewConnectionId(_) | Frame::RetireConnectionId(_) => {
                // Accept and ignore for now
            }

            Frame::PathChallenge(_) | Frame::PathResponse(_) => {
                // Skip connection migration
            }

            Frame::DataBlocked(_)
            | Frame::StreamDataBlocked(_)
            | Frame::StreamsBlocked(_) => {
                // Informational; peer is blocked. No action needed.
            }
        }

        Ok(())
    }

    /// Handle a CRYPTO frame: buffer data and feed to TLS engine.
    fn handle_crypto_frame(
        &mut self,
        level: Level,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error> {
        // Reject CRYPTO frames with very large offsets that could cause
        // resource exhaustion or overflow issues.
        const MAX_CRYPTO_OFFSET: u64 = 1 << 20; // 1 MiB should be more than enough for TLS
        if offset > MAX_CRYPTO_OFFSET || offset.saturating_add(data.len() as u64) > MAX_CRYPTO_OFFSET {
            return Err(Error::Transport(
                crate::error::TransportError::CryptoBufferExceeded,
            ));
        }

        let idx = level_index(level);

        // For simplicity, we only handle in-order crypto data.
        // If offset matches our expected offset, buffer and process.
        let expected = self.crypto_recv_offset[idx];
        if offset != expected {
            // Out of order: if offset < expected, it's a retransmit we already processed.
            // If offset > expected, we'd need reassembly. For now, just ignore.
            if offset < expected {
                return Ok(());
            }
            // Gap detected: can't process yet. In a full implementation we'd buffer.
            return Ok(());
        }

        // Append to crypto receive buffer
        let buf = &mut self.crypto_recv_buf[idx];
        let start = buf.len();
        if start + data.len() > buf.capacity() {
            return Err(Error::Transport(
                crate::error::TransportError::CryptoBufferExceeded,
            ));
        }
        let _ = buf.extend_from_slice(data);
        self.crypto_recv_offset[idx] = offset + data.len() as u64;

        // Feed all buffered crypto data to TLS engine
        let crypto_data_copy = {
            let mut tmp = [0u8; 4096];
            let len = buf.len();
            if len > tmp.len() {
                return Err(Error::Tls);
            }
            tmp[..len].copy_from_slice(buf);
            (tmp, len)
        };

        // Clear the buffer after copying
        self.crypto_recv_buf[idx].clear();

        self.tls
            .read_handshake(level, &crypto_data_copy.0[..crypto_data_copy.1])?;

        // Check for newly derived keys
        self.check_tls_keys()?;

        Ok(())
    }

    /// Check if TLS engine has produced new keys and install them.
    #[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
    fn check_tls_keys(&mut self) -> Result<(), Error> {
        while let Some(derived) = self.tls.derived_keys() {
            let level = derived.level;
            self.keys.install_derived(&self.crypto, &derived)?;

            match level {
                Level::Handshake => {
                    // When handshake keys arrive on the client side, we can
                    // drop Initial keys (the client already sent its ClientHello).
                    // On the server side, we still need Initial keys to send
                    // the ServerHello, so defer dropping until after that.
                    if self.role == crate::tls::handshake::Role::Client {
                        self.keys.drop_initial();
                        self.sent_tracker.drop_space(Level::Initial);
                        self.loss_detector.drop_space(Level::Initial);
                    }
                }
                Level::Application => {
                    // Application keys ready. For server, transition to Active.
                    if self.role == crate::tls::handshake::Role::Server
                        && matches!(self.state, ConnectionState::Handshaking)
                    {
                        // Server considers handshake complete when it has app keys
                        // (it already sent HANDSHAKE_DONE in poll_transmit)
                        // but the transition to Active happens when the client's
                        // Finished is received and app keys are derived
                        self.state = ConnectionState::Active;
                        self.address_validated = true;
                        let _ = self.events.push_back(Event::Connected);
                        // Server drops handshake keys after confirming
                        self.keys.drop_handshake();
                        self.sent_tracker.drop_space(Level::Handshake);
                        self.loss_detector.drop_space(Level::Handshake);
                    }
                }
                _ => {}
            }

            // Store peer transport params if available
            if let Some(peer_params) = self.tls.peer_transport_params() {
                // Update flow control with peer's limits
                self.flow_control
                    .handle_max_data(peer_params.initial_max_data);
                self.flow_control
                    .handle_max_streams(true, peer_params.initial_max_streams_bidi);
                self.flow_control
                    .handle_max_streams(false, peer_params.initial_max_streams_uni);
                self.peer_params = Some(peer_params.clone());
            }
        }
        Ok(())
    }

    #[cfg(not(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes")))]
    fn check_tls_keys(&mut self) -> Result<(), Error> {
        // Without crypto features, we can't install keys
        Ok(())
    }
}

/// Map Level to array index 0..3.
pub(crate) fn level_index(level: Level) -> usize {
    match level {
        Level::Initial => 0,
        Level::Handshake => 1,
        Level::Application => 2,
    }
}

use super::ConnectionId;
