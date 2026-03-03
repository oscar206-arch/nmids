"""
traffic_generator.py
Generates simulated packet metadata for 11 configurable attack scenarios.
No raw sockets, Scapy, or root privileges required.
"""

import random
import time
import threading
from datetime import datetime

# ─── IP pools ─────────────────────────────────────────────────────────────────
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
EXTERNAL_IPS = [f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                for _ in range(20)]
ATTACKER_IPS = ["10.0.0.99", "172.16.100.5", "45.33.32.156", "198.51.100.23"]
SERVER_IPS   = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "FTP", "SSH"]

SUSPICIOUS_PORTS = [4444, 6667, 1337, 31337, 12345, 9001, 6660, 4899]
AUTH_PORTS       = [22, 21, 3389, 5900, 23]
COMMON_PORTS     = [80, 443, 8080, 8443, 53, 25, 110, 143, 3306, 5432]

TCP_FLAGS = ["SYN", "ACK", "SYN-ACK", "FIN", "RST", "PSH-ACK", ""]


# ─── Scenario packet factories ────────────────────────────────────────────────

def _packet(src, dst, proto, size, port, flags="", ts=None):
    return {
        "timestamp":   ts or datetime.now().isoformat(timespec='seconds'),
        "src_ip":      src,
        "dst_ip":      dst,
        "protocol":    proto,
        "packet_size": size,
        "port":        port,
        "flags":       flags,
        "is_anomaly":  False,
        "anomaly_type": ""
    }


def _normal_packet():
    src  = random.choice(INTERNAL_IPS)
    dst  = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:5])
    proto = random.choice(["TCP", "UDP", "HTTP", "HTTPS", "DNS"])
    size = random.randint(40, 800)
    port = random.choice(COMMON_PORTS)
    flags = random.choice(TCP_FLAGS[:4])
    return _packet(src, dst, proto, size, port, flags)


def _port_scan_packet():
    src  = random.choice(ATTACKER_IPS)
    dst  = random.choice(SERVER_IPS)
    port = random.randint(1, 65535)          # sweeping ports
    return _packet(src, dst, "TCP", random.randint(40, 60), port, "SYN")


def _ddos_packet():
    src  = random.choice(EXTERNAL_IPS)
    dst  = random.choice(SERVER_IPS)
    proto = random.choice(["UDP", "TCP", "ICMP"])
    size = random.randint(500, 1500)
    port = random.choice([80, 443])
    return _packet(src, dst, proto, size, port, "SYN")


def _brute_force_packet():
    src  = random.choice(ATTACKER_IPS)
    dst  = random.choice(SERVER_IPS)
    port = random.choice(AUTH_PORTS)
    return _packet(src, dst, "TCP", random.randint(60, 120), port, "SYN")


def _syn_flood_packet():
    src  = random.choice(EXTERNAL_IPS)
    dst  = random.choice(SERVER_IPS)
    return _packet(src, dst, "TCP", random.randint(40, 60),
                   random.choice([80, 443]), "SYN")


def _suspicious_port_packet():
    src  = random.choice(ATTACKER_IPS + EXTERNAL_IPS[:3])
    dst  = random.choice(INTERNAL_IPS)
    port = random.choice(SUSPICIOUS_PORTS)
    return _packet(src, dst, "TCP", random.randint(100, 400), port, "SYN-ACK")


def _large_packet():
    src  = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:3])
    dst  = random.choice(INTERNAL_IPS)
    proto = random.choice(["TCP", "UDP"])
    size = random.randint(1401, 9000)        # deliberately oversized
    return _packet(src, dst, proto, size, random.choice(COMMON_PORTS))


def _icmp_flood_packet():
    src  = random.choice(EXTERNAL_IPS + ATTACKER_IPS)
    dst  = random.choice(SERVER_IPS)
    return _packet(src, dst, "ICMP", random.randint(64, 128),
                   0, "ECHO-REQUEST")


def _arp_spoof_packet():
    src  = random.choice(ATTACKER_IPS)
    dst  = random.choice(INTERNAL_IPS)
    return _packet(src, dst, "ARP", random.randint(28, 60), 0, "ARP-REPLY")


def _dns_tunnel_packet():
    src  = random.choice(ATTACKER_IPS)
    dst  = random.choice(["8.8.8.8", "1.1.1.1"])
    size = random.randint(151, 512)          # oversized DNS → tunnelling
    return _packet(src, dst, "DNS", size, 53)


def _mixed_packet():
    generators = [
        _normal_packet, _port_scan_packet, _syn_flood_packet,
        _suspicious_port_packet, _large_packet, _brute_force_packet
    ]
    weights = [50, 10, 10, 10, 10, 10]
    return random.choices(generators, weights=weights)[0]()


# ─── Scenario map ─────────────────────────────────────────────────────────────

SCENARIO_GENERATORS = {
    "normal":          _normal_packet,
    "port_scan":       _port_scan_packet,
    "ddos":            _ddos_packet,
    "brute_force":     _brute_force_packet,
    "syn_flood":       _syn_flood_packet,
    "suspicious_port": _suspicious_port_packet,
    "large_packet":    _large_packet,
    "icmp_flood":      _icmp_flood_packet,
    "arp_spoofing":    _arp_spoof_packet,
    "dns_tunnel":      _dns_tunnel_packet,
    "mixed":           _mixed_packet,
}

SCENARIO_DESCRIPTIONS = {
    "normal":          "Baseline HTTP/HTTPS/DNS traffic between internal hosts",
    "port_scan":       "Attacker probing sequential ports on server hosts",
    "ddos":            "Distributed volumetric flood from multiple external IPs",
    "brute_force":     "Repeated auth attempts on SSH, FTP, RDP, VNC, Telnet",
    "syn_flood":       "TCP SYN flood targeting web servers (no ACK completes)",
    "suspicious_port": "Connections to known C2 / malware ports (Metasploit, IRC, etc.)",
    "large_packet":    "Oversized packets suggesting fragmentation or data exfiltration",
    "icmp_flood":      "High-rate ICMP echo flood overwhelming network devices",
    "arp_spoofing":    "ARP reply injection to poison MAC/IP mappings",
    "dns_tunnel":      "Oversized DNS queries encoding data in subdomain labels",
    "mixed":           "Randomised mix of normal and attack traffic",
}


# ─── TrafficGenerator class ───────────────────────────────────────────────────

class TrafficGenerator:
    """
    Runs the packet generation loop in a background daemon thread.
    Calls on_packet(packet_dict) for every generated packet.
    """

    def __init__(self, on_packet):
        self.on_packet    = on_packet
        self.scenario     = "normal"
        self.rate         = 2.0          # packets per second (0.5 – 20)
        self._running     = False
        self._thread      = None
        self._lock        = threading.Lock()

    def start(self, scenario="normal", rate=2.0):
        with self._lock:
            if self._running:
                return
            self.scenario = scenario
            self.rate     = max(0.5, min(20.0, float(rate)))
            self._running = True
            self._thread  = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self):
        with self._lock:
            self._running = False

    def update(self, scenario=None, rate=None):
        with self._lock:
            if scenario is not None:
                self.scenario = scenario
            if rate is not None:
                self.rate = max(0.5, min(20.0, float(rate)))

    def is_running(self):
        return self._running

    def _loop(self):
        while self._running:
            try:
                gen = SCENARIO_GENERATORS.get(self.scenario, _normal_packet)
                pkt = gen()
                self.on_packet(pkt)
            except Exception as e:
                print(f"[TrafficGenerator] Error: {e}")
            interval = 1.0 / max(0.5, self.rate)
            time.sleep(interval)
        # thread exits cleanly
