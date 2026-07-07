"""
detector.py
-----------
The rule engine. Takes parsed packet info (dicts) one at a time and checks
them against a set of stateful rules using sliding time windows.

Each rule tracks recent activity per source IP using deques of timestamps,
so old activity automatically "ages out" of the window.
"""

import time
from collections import defaultdict, deque

import config
from logger import log_alert, log_info


class IntrusionDetector:
    def __init__(self):
        # src_ip -> deque of (timestamp, dst_port) for port scan detection
        self.port_activity = defaultdict(deque)

        # src_ip -> deque of timestamps for SYN flood detection
        self.syn_activity = defaultdict(deque)

        # (src_ip, dst_port) -> deque of timestamps for repeated-connection / brute force detection
        self.conn_activity = defaultdict(deque)

        # Track which (src_ip) we've already alerted for a given category recently,
        # to avoid spamming the same alert every single packet.
        self.recent_alerts = {}
        self.ALERT_COOLDOWN = 5  # seconds before re-alerting same src+category

        self.stats = {
            "packets_processed": 0,
            "alerts_raised": 0,
        }

    # ------------------------------------------------------------------
    # Helper: avoid re-alerting the same (src_ip, category) every packet
    # ------------------------------------------------------------------
    def _should_alert(self, src_ip: str, category: str) -> bool:
        key = (src_ip, category)
        now = time.time()
        last = self.recent_alerts.get(key, 0)
        if now - last >= self.ALERT_COOLDOWN:
            self.recent_alerts[key] = now
            return True
        return False

    # ------------------------------------------------------------------
    # Helper: trim a deque of timestamps to only keep entries within window
    # ------------------------------------------------------------------
    @staticmethod
    def _trim(dq: deque, window: float, now: float, key_fn=lambda x: x):
        while dq and now - key_fn(dq[0]) > window:
            dq.popleft()

    # ------------------------------------------------------------------
    # Main entry point - called once per captured packet
    # ------------------------------------------------------------------
    def process_packet(self, pkt_info: dict):
        self.stats["packets_processed"] += 1
        now = time.time()

        src_ip = pkt_info.get("src_ip")
        dst_ip = pkt_info.get("dst_ip")
        dst_port = pkt_info.get("dst_port")
        flags = pkt_info.get("flags", "")
        payload_len = pkt_info.get("payload_len", 0)

        if not src_ip:
            return

        self._check_blacklist(src_ip, dst_ip)
        self._check_suspicious_port(src_ip, dst_ip, dst_port)
        self._check_oversized_payload(src_ip, dst_ip, payload_len)

        if dst_port is not None:
            self._check_port_scan(src_ip, dst_ip, dst_port, now)
            self._check_repeat_connections(src_ip, dst_ip, dst_port, now)

        if "S" in flags and "A" not in flags:  # SYN without ACK = new connection attempt
            self._check_syn_flood(src_ip, dst_ip, now)

    # ------------------------------------------------------------------
    # Rule: Blacklisted IP
    # ------------------------------------------------------------------
    def _check_blacklist(self, src_ip, dst_ip):
        if src_ip in config.BLACKLISTED_IPS or dst_ip in config.BLACKLISTED_IPS:
            if self._should_alert(src_ip, "BLACKLIST"):
                log_alert("HIGH", "BLACKLIST", src_ip, dst_ip,
                          "Traffic involves a blacklisted IP address")
                self.stats["alerts_raised"] += 1

    # ------------------------------------------------------------------
    # Rule: Suspicious port
    # ------------------------------------------------------------------
    def _check_suspicious_port(self, src_ip, dst_ip, dst_port):
        if dst_port in config.SUSPICIOUS_PORTS:
            if self._should_alert(src_ip, f"SUSPICIOUS_PORT_{dst_port}"):
                reason = config.SUSPICIOUS_PORTS[dst_port]
                log_alert("LOW", "SUSPICIOUS_PORT", src_ip, dst_ip,
                          f"Connection to port {dst_port} ({reason})")
                self.stats["alerts_raised"] += 1

    # ------------------------------------------------------------------
    # Rule: Oversized payload
    # ------------------------------------------------------------------
    def _check_oversized_payload(self, src_ip, dst_ip, payload_len):
        if payload_len and payload_len > config.MAX_PAYLOAD_BYTES:
            if self._should_alert(src_ip, "OVERSIZED_PAYLOAD"):
                log_alert("MEDIUM", "OVERSIZED_PAYLOAD", src_ip, dst_ip,
                          f"Unusually large payload: {payload_len} bytes")
                self.stats["alerts_raised"] += 1

    # ------------------------------------------------------------------
    # Rule: Port scan - many distinct ports from one src in short window
    # ------------------------------------------------------------------
    def _check_port_scan(self, src_ip, dst_ip, dst_port, now):
        dq = self.port_activity[src_ip]
        dq.append((now, dst_port))
        self._trim(dq, config.PORT_SCAN_WINDOW, now, key_fn=lambda x: x[0])

        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) >= config.PORT_SCAN_THRESHOLD:
            if self._should_alert(src_ip, "PORT_SCAN"):
                log_alert("HIGH", "PORT_SCAN", src_ip, dst_ip,
                          f"{len(distinct_ports)} distinct ports contacted in "
                          f"{config.PORT_SCAN_WINDOW}s (possible port scan)")
                self.stats["alerts_raised"] += 1

    # ------------------------------------------------------------------
    # Rule: SYN flood - many SYN packets from one src in short window
    # ------------------------------------------------------------------
    def _check_syn_flood(self, src_ip, dst_ip, now):
        dq = self.syn_activity[src_ip]
        dq.append(now)
        self._trim(dq, config.SYN_FLOOD_WINDOW, now)

        if len(dq) >= config.SYN_FLOOD_THRESHOLD:
            if self._should_alert(src_ip, "SYN_FLOOD"):
                log_alert("HIGH", "SYN_FLOOD", src_ip, dst_ip,
                          f"{len(dq)} SYN packets in {config.SYN_FLOOD_WINDOW}s "
                          f"(possible SYN flood / DoS)")
                self.stats["alerts_raised"] += 1

    # ------------------------------------------------------------------
    # Rule: Repeated connections to same port (brute-force-ish behavior)
    # ------------------------------------------------------------------
    def _check_repeat_connections(self, src_ip, dst_ip, dst_port, now):
        key = (src_ip, dst_port)
        dq = self.conn_activity[key]
        dq.append(now)
        self._trim(dq, config.REPEAT_CONN_WINDOW, now)

        if len(dq) >= config.REPEAT_CONN_THRESHOLD:
            if self._should_alert(src_ip, f"REPEAT_CONN_{dst_port}"):
                log_alert("MEDIUM", "REPEATED_CONNECTIONS", src_ip, dst_ip,
                          f"{len(dq)} connections to port {dst_port} in "
                          f"{config.REPEAT_CONN_WINDOW}s (possible brute force)")
                self.stats["alerts_raised"] += 1

    def print_summary(self):
        log_info(f"Packets processed: {self.stats['packets_processed']} | "
                  f"Alerts raised: {self.stats['alerts_raised']}")
