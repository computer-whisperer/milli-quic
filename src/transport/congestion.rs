use crate::Instant;

pub struct CongestionController {
    /// Congestion window in bytes.
    cwnd: u64,
    /// Slow start threshold.
    ssthresh: u64,
    /// Bytes in flight (sent but not yet acked or declared lost).
    bytes_in_flight: u64,
    /// Recovery start time (None if not in recovery).
    recovery_start_time: Option<Instant>,
    /// Persistent congestion threshold.
    persistent_congestion_threshold: u64,

    max_datagram_size: u64,
    minimum_window: u64,
}

impl CongestionController {
    /// Create with default QUIC parameters.
    /// initial_window = max(10 * max_datagram_size, 14720)
    /// minimum_window = 2 * max_datagram_size
    pub fn new(max_datagram_size: u64) -> Self {
        let minimum_window = 2 * max_datagram_size;
        let initial_window = (10 * max_datagram_size).max(14_720);
        Self {
            cwnd: initial_window,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            recovery_start_time: None,
            persistent_congestion_threshold: 0,
            max_datagram_size,
            minimum_window,
        }
    }

    /// Can we send `bytes` right now?
    pub fn can_send(&self, bytes: u64) -> bool {
        self.bytes_in_flight + bytes <= self.cwnd
    }

    /// Available send window.
    pub fn available_window(&self) -> u64 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    /// Record bytes sent (in-flight).
    pub fn on_packet_sent(&mut self, bytes: u64) {
        self.bytes_in_flight += bytes;
    }

    /// Packet was acknowledged.
    /// `sent_time` is when the packet was originally sent.
    pub fn on_packet_acked(&mut self, bytes: u64, sent_time: Instant, _now: Instant) {
        self.remove_from_flight(bytes);

        // Don't increase cwnd if the packet was sent during a previous recovery period.
        if let Some(recovery_start) = self.recovery_start_time {
            if sent_time <= recovery_start {
                return;
            }
        }

        if self.in_slow_start() {
            // Slow start: increase cwnd by bytes acknowledged.
            self.cwnd += bytes;
        } else {
            // Congestion avoidance: increase by ~1 MSS per RTT.
            // cwnd += max_datagram_size * bytes / cwnd
            self.cwnd += self.max_datagram_size * bytes / self.cwnd;
        }
    }

    /// Packet was declared lost.
    pub fn on_packet_lost(&mut self, bytes: u64, sent_time: Instant, now: Instant) {
        self.remove_from_flight(bytes);

        // Don't re-enter recovery if this packet was sent before recovery started.
        if self.in_recovery(sent_time) {
            return;
        }

        // Enter recovery.
        self.recovery_start_time = Some(now);
        self.ssthresh = (self.cwnd / 2).max(self.minimum_window);
        self.cwnd = self.ssthresh;
    }

    /// Handle persistent congestion (RFC 9002 §7.6.2).
    pub fn on_persistent_congestion(&mut self) {
        self.cwnd = self.minimum_window;
        self.recovery_start_time = None;
    }

    /// Bytes currently in flight.
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Current congestion window.
    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }

    /// Current slow start threshold.
    pub fn ssthresh(&self) -> u64 {
        self.ssthresh
    }

    /// Are we in slow start?
    pub fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// Are we in recovery? A packet sent at `sent_time` is "in recovery"
    /// if it was sent at or before the recovery start.
    pub fn in_recovery(&self, sent_time: Instant) -> bool {
        match self.recovery_start_time {
            Some(start) => sent_time <= start,
            None => false,
        }
    }

    /// Set the persistent congestion threshold.
    /// Typically: 3 * (smoothed_rtt + max(4*rttvar, granularity)) * 2^pto_count
    pub fn set_persistent_congestion_threshold(&mut self, threshold: u64) {
        self.persistent_congestion_threshold = threshold;
    }

    /// Get the persistent congestion threshold.
    pub fn persistent_congestion_threshold(&self) -> u64 {
        self.persistent_congestion_threshold
    }

    fn remove_from_flight(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MDS: u64 = 1200; // typical QUIC max datagram size

    #[test]
    fn initial_state() {
        let cc = CongestionController::new(MDS);
        assert_eq!(cc.cwnd(), 14_720); // max(10*1200=12000, 14720) = 14720
        assert_eq!(cc.ssthresh(), u64::MAX);
        assert!(cc.in_slow_start());
        assert_eq!(cc.bytes_in_flight(), 0);
        assert!(cc.can_send(1200));
    }

    #[test]
    fn initial_window_large_mds() {
        // With MDS=1500, 10*1500=15000 > 14720.
        let cc = CongestionController::new(1500);
        assert_eq!(cc.cwnd(), 15_000);
    }

    #[test]
    fn slow_start_increase() {
        let mut cc = CongestionController::new(MDS);
        let initial = cc.cwnd();

        cc.on_packet_sent(1200);
        assert_eq!(cc.bytes_in_flight(), 1200);

        cc.on_packet_acked(1200, 1000, 2000);
        assert_eq!(cc.cwnd(), initial + 1200);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn slow_start_to_congestion_avoidance() {
        let mut cc = CongestionController::new(MDS);

        // Force ssthresh to a specific value by triggering a loss.
        // First, increase cwnd in slow start.
        for i in 0..10 {
            cc.on_packet_sent(1200);
            cc.on_packet_acked(1200, i * 1000, (i + 1) * 1000);
        }
        let cwnd_before_loss = cc.cwnd();

        // Trigger loss to set ssthresh.
        cc.on_packet_sent(1200);
        cc.on_packet_lost(1200, 11_000, 12_000);
        let expected_ssthresh = (cwnd_before_loss / 2).max(2 * MDS);
        assert_eq!(cc.ssthresh(), expected_ssthresh);
        assert_eq!(cc.cwnd(), expected_ssthresh);
        assert!(!cc.in_slow_start()); // cwnd == ssthresh, so not < ssthresh
    }

    #[test]
    fn congestion_avoidance_increase() {
        let mut cc = CongestionController::new(MDS);
        // Set up congestion avoidance by forcing a loss.
        cc.on_packet_sent(1200);
        cc.on_packet_lost(1200, 1000, 2000);
        // Now cwnd == ssthresh, so in congestion avoidance.
        let cwnd_after = cc.cwnd();

        // Send and ack a packet (sent after recovery_start_time).
        cc.on_packet_sent(1200);
        cc.on_packet_acked(1200, 3000, 4000);
        // Congestion avoidance: cwnd += max_datagram_size * bytes / cwnd
        // = 1200 * 1200 / cwnd_after
        let expected_increase = MDS * 1200 / cwnd_after;
        assert_eq!(cc.cwnd(), cwnd_after + expected_increase);
    }

    #[test]
    fn loss_triggers_recovery() {
        let mut cc = CongestionController::new(MDS);
        let initial = cc.cwnd();

        cc.on_packet_sent(1200);
        cc.on_packet_lost(1200, 1000, 2000);

        let expected_ssthresh = (initial / 2).max(2 * MDS);
        assert_eq!(cc.ssthresh(), expected_ssthresh);
        assert_eq!(cc.cwnd(), expected_ssthresh);
        assert!(cc.in_recovery(1000)); // sent before recovery start
        assert!(cc.in_recovery(2000)); // sent at recovery start
        assert!(!cc.in_recovery(2001)); // sent after
    }

    #[test]
    fn no_double_recovery() {
        let mut cc = CongestionController::new(MDS);

        // First loss at time 2000.
        cc.on_packet_sent(1200);
        cc.on_packet_lost(1200, 1000, 2000);
        let cwnd_after_first_loss = cc.cwnd();

        // Second loss of a packet also sent before recovery start.
        cc.on_packet_sent(1200);
        cc.on_packet_lost(1200, 500, 3000); // sent_time=500, before recovery_start=2000
        // Should NOT re-enter recovery.
        assert_eq!(cc.cwnd(), cwnd_after_first_loss);
    }

    #[test]
    fn persistent_congestion() {
        let mut cc = CongestionController::new(MDS);
        cc.on_persistent_congestion();
        assert_eq!(cc.cwnd(), 2 * MDS);
        assert!(cc.recovery_start_time.is_none());
    }

    #[test]
    fn bytes_in_flight_tracking() {
        let mut cc = CongestionController::new(MDS);
        cc.on_packet_sent(1200);
        cc.on_packet_sent(1200);
        assert_eq!(cc.bytes_in_flight(), 2400);

        cc.on_packet_acked(1200, 1000, 2000);
        assert_eq!(cc.bytes_in_flight(), 1200);

        cc.on_packet_lost(1200, 1000, 3000);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn can_send_respects_window() {
        let mut cc = CongestionController::new(MDS);
        let cwnd = cc.cwnd();

        assert!(cc.can_send(cwnd));
        assert!(!cc.can_send(cwnd + 1));

        cc.on_packet_sent(cwnd - 1200);
        assert!(cc.can_send(1200));
        assert!(!cc.can_send(1201));
    }

    #[test]
    fn available_window() {
        let mut cc = CongestionController::new(MDS);
        assert_eq!(cc.available_window(), cc.cwnd());

        cc.on_packet_sent(5000);
        assert_eq!(cc.available_window(), cc.cwnd() - 5000);
    }

    #[test]
    fn acked_during_recovery_no_increase() {
        let mut cc = CongestionController::new(MDS);
        // Send two packets.
        cc.on_packet_sent(1200); // sent at time 1000
        cc.on_packet_sent(1200); // sent at time 1500

        // Lose the first packet, entering recovery at time 2000.
        cc.on_packet_lost(1200, 1000, 2000);
        let cwnd_in_recovery = cc.cwnd();

        // ACK the second packet, which was sent at 1500 <= recovery_start(2000).
        cc.on_packet_acked(1200, 1500, 2500);
        // cwnd should not increase since the packet was sent during recovery.
        assert_eq!(cc.cwnd(), cwnd_in_recovery);
    }
}
