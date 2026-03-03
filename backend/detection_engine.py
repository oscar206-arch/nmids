"""
detection_engine.py
Implements 8 stateful intrusion detection rules using sliding-window counters.
Thread-safe for concurrent access from traffic generator thread.

Rules:
  R1  Port scan        – 1 src probes >15 unique dst ports in 10 s  → HIGH
  R2  Traffic flood    – 1 src sends >100 packets in 5 s             → CRITICAL
  R3  SYN flood        – >20 TCP SYN (no ACK) to 1 dst in 10 s      → CRITICAL
  R4  Brute force      – >20 auth-port connections from 1 src in 10s → HIGH
  R5  Oversized packet – any packet >1400 bytes                       → MEDIUM
  R6  Suspicious port  – connection to known malicious port           → MEDIUM
  R7  ARP spoofing     – any ARP packet                               → HIGH
  R8  DNS tunnelling   – DNS packet >150 bytes                        → HIGH
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime

# ─── Rule thresholds ──────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD    = 15    # unique ports
PORT_SCAN_WINDOW       = 10    # seconds

FLOOD_THRESHOLD        = 100   # packets
FLOOD_WINDOW           = 5     # seconds

SYN_FLOOD_THRESHOLD    = 20    # SYN packets
SYN_FLOOD_WINDOW       = 10    # seconds

BRUTE_FORCE_THRESHOLD  = 20    # connection attempts
BRUTE_FORCE_WINDOW     = 10    # seconds

OVERSIZED_THRESHOLD    = 1400  # bytes

SUSPICIOUS_PORTS = {4444, 6667, 1337, 31337, 12345, 9001, 6660, 4899}
AUTH_PORTS       = {22, 21, 3389, 5900, 23}

DNS_TUNNEL_THRESHOLD   = 150   # bytes


class DetectionEngine:
    """
    Stateful rule evaluator. Call analyse(packet) for each generated packet.
    If an anomaly is detected, on_alert(alert_dict) is called immediately.
    Learning mode suppresses alert dispatch while still profiling traffic.
    """

    def __init__(self, on_alert):
        self.on_alert      = on_alert
        self.learning_mode = False
        self._lock         = threading.Lock()

        # Sliding-window state: deques of timestamps
        # key: src_ip
        self._port_scan_ports:  dict[str, dict]  = defaultdict(lambda: defaultdict(deque))
        self._flood_times:      dict[str, deque] = defaultdict(deque)
        self._brute_times:      dict[str, deque] = defaultdict(deque)

        # key: dst_ip
        self._syn_times:        dict[str, deque] = defaultdict(deque)

        # Baseline profiling (learning mode)
        self._baseline_data: dict[str, list] = defaultdict(list)

    # ─── Public API ───────────────────────────────────────────────────────────

    def analyse(self, packet: dict) -> dict:
        """
        Evaluate all 8 rules against packet.
        Returns the packet dict annotated with is_anomaly / anomaly_type.
        Dispatches on_alert for any triggered rule (unless learning mode).
        """
        now      = time.time()
        src      = packet.get('src_ip', '')
        dst      = packet.get('dst_ip', '')
        proto    = packet.get('protocol', '')
        size     = packet.get('packet_size', 0)
        port     = packet.get('port', 0)
        flags    = packet.get('flags', '')

        alerts_triggered = []

        with self._lock:
            # R1 – Port scan
            if proto == "TCP" and flags == "SYN":
                window = self._port_scan_ports[src]
                window[port].append(now)
                # prune stale entries
                for p in list(window.keys()):
                    window[p] = deque(t for t in window[p] if now - t <= PORT_SCAN_WINDOW)
                    if not window[p]:
                        del window[p]
                unique_ports = len(window)
                if unique_ports > PORT_SCAN_THRESHOLD:
                    alerts_triggered.append(self._make_alert(
                        packet, "port_scan", "HIGH",
                        f"Port scan detected: {unique_ports} unique ports probed from {src} in {PORT_SCAN_WINDOW}s"
                    ))

            # R2 – Traffic flood
            q = self._flood_times[src]
            q.append(now)
            while q and now - q[0] > FLOOD_WINDOW:
                q.popleft()
            if len(q) > FLOOD_THRESHOLD:
                alerts_triggered.append(self._make_alert(
                    packet, "traffic_flood", "CRITICAL",
                    f"Traffic flood: {len(q)} packets from {src} in {FLOOD_WINDOW}s"
                ))

            # R3 – SYN flood
            if proto == "TCP" and flags == "SYN":
                q2 = self._syn_times[dst]
                q2.append(now)
                while q2 and now - q2[0] > SYN_FLOOD_WINDOW:
                    q2.popleft()
                if len(q2) > SYN_FLOOD_THRESHOLD:
                    alerts_triggered.append(self._make_alert(
                        packet, "syn_flood", "CRITICAL",
                        f"SYN flood: {len(q2)} SYN packets targeting {dst} in {SYN_FLOOD_WINDOW}s"
                    ))

            # R4 – Brute force
            if port in AUTH_PORTS:
                q3 = self._brute_times[src]
                q3.append(now)
                while q3 and now - q3[0] > BRUTE_FORCE_WINDOW:
                    q3.popleft()
                if len(q3) > BRUTE_FORCE_THRESHOLD:
                    alerts_triggered.append(self._make_alert(
                        packet, "brute_force", "HIGH",
                        f"Brute force: {len(q3)} auth attempts from {src} to port {port} in {BRUTE_FORCE_WINDOW}s"
                    ))

            # R5 – Oversized packet
            if size > OVERSIZED_THRESHOLD:
                alerts_triggered.append(self._make_alert(
                    packet, "large_packet", "MEDIUM",
                    f"Oversized packet: {size} bytes from {src} (threshold {OVERSIZED_THRESHOLD})"
                ))

            # R6 – Suspicious port
            if port in SUSPICIOUS_PORTS:
                alerts_triggered.append(self._make_alert(
                    packet, "suspicious_port", "MEDIUM",
                    f"Connection to suspicious port {port} from {src} → {dst}"
                ))

            # R7 – ARP spoofing
            if proto == "ARP":
                alerts_triggered.append(self._make_alert(
                    packet, "arp_spoofing", "HIGH",
                    f"ARP packet detected from {src}: possible MAC/IP poisoning"
                ))

            # R8 – DNS tunnelling
            if proto == "DNS" and size > DNS_TUNNEL_THRESHOLD:
                alerts_triggered.append(self._make_alert(
                    packet, "dns_tunnel", "HIGH",
                    f"DNS tunnel suspected: {size}-byte DNS packet from {src} (threshold {DNS_TUNNEL_THRESHOLD})"
                ))

        # Annotate packet
        if alerts_triggered:
            packet['is_anomaly']   = True
            packet['anomaly_type'] = ', '.join(a['alert_type'] for a in alerts_triggered)

        # Dispatch alerts (skipped in learning mode)
        if not self.learning_mode:
            for alert in alerts_triggered:
                try:
                    self.on_alert(alert)
                except Exception as e:
                    print(f"[DetectionEngine] Alert dispatch error: {e}")
        else:
            # Collect baseline data
            self._baseline_data[proto].append(size)

        return packet

    def get_baseline_stats(self) -> dict:
        """Return per-protocol averages from learning mode data."""
        stats = {}
        with self._lock:
            for proto, sizes in self._baseline_data.items():
                if sizes:
                    stats[proto] = {
                        'avg_size':     sum(sizes) / len(sizes),
                        'sample_count': len(sizes)
                    }
        return stats

    def reset_state(self):
        """Clear all sliding-window counters (e.g. when simulation restarts)."""
        with self._lock:
            self._port_scan_ports.clear()
            self._flood_times.clear()
            self._brute_times.clear()
            self._syn_times.clear()

    # ─── Internal helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _make_alert(packet: dict, alert_type: str, severity: str, description: str) -> dict:
        return {
            'timestamp':  datetime.now().isoformat(timespec='seconds'),
            'alert_type': alert_type,
            'severity':   severity,
            'src_ip':     packet.get('src_ip', ''),
            'dst_ip':     packet.get('dst_ip', ''),
            'description': description,
        }
