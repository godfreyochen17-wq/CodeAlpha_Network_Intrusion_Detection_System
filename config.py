"""
config.py
----------
Central place for all NIDS detection thresholds and settings.
Tune these values to make the demo more/less sensitive.
"""

# Network interface to sniff on. Leave as None to let scapy pick the default,
# or set to a specific interface name (see: python -c "from scapy.all import show_interfaces; show_interfaces()")
INTERFACE = None

# --- Port Scan Detection ---
# If a single source IP contacts this many DISTINCT destination ports
# within PORT_SCAN_WINDOW seconds, flag it as a port scan.
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 10  # seconds

# --- SYN Flood / DoS Detection ---
# If a single source IP sends this many SYN packets within SYN_FLOOD_WINDOW
# seconds, flag it as a possible SYN flood / DoS attempt.
SYN_FLOOD_THRESHOLD = 50
SYN_FLOOD_WINDOW = 10  # seconds

# --- Repeated Connection Attempts (brute force-ish behavior) ---
# If a single source IP opens this many connections to the SAME
# destination port within the window, flag it (e.g. SSH/RDP brute force).
REPEAT_CONN_THRESHOLD = 20
REPEAT_CONN_WINDOW = 15  # seconds

# --- Blacklisted IPs ---
# Any traffic to/from these IPs is immediately flagged.
BLACKLISTED_IPS = {
    "203.0.113.66",   # example malicious IP (TEST-NET-3, safe example range)
    "198.51.100.23",  # example malicious IP (TEST-NET-2, safe example range)
}

# --- Suspicious / commonly attacked ports ---
# Traffic to these ports gets logged with a lower-severity notice.
SUSPICIOUS_PORTS = {
    23: "Telnet (insecure, often targeted)",
    445: "SMB (EternalBlue-style exploits)",
    3389: "RDP (common brute force target)",
    3306: "MySQL (should rarely be internet-facing)",
    21: "FTP (often unencrypted credentials)",
}

# --- Oversized payload detection ---
# Flags packets with unusually large payloads (possible exfiltration / exploit attempt)
MAX_PAYLOAD_BYTES = 4096

# --- Logging ---
LOG_FILE = "logs/alerts.log"
