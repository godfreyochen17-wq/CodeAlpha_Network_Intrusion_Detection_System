"""
sniffer.py
----------
Captures live network packets using scapy and converts each one into a
simple dict of the fields the detector cares about.

On Windows, this requires Npcap to be installed (https://npcap.com/) and
the script to be run from an elevated (Administrator) terminal.
"""

from scapy.all import sniff, IP, TCP, UDP, Raw

import config
from logger import log_info


def _parse_packet(pkt):
    """Extract only the fields we need into a plain dict."""
    if IP not in pkt:
        return None

    info = {
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "dst_port": None,
        "flags": "",
        "payload_len": 0,
        "protocol": "OTHER",
    }

    if TCP in pkt:
        info["dst_port"] = pkt[TCP].dport
        info["flags"] = str(pkt[TCP].flags)
        info["protocol"] = "TCP"
    elif UDP in pkt:
        info["dst_port"] = pkt[UDP].dport
        info["protocol"] = "UDP"

    if Raw in pkt:
        info["payload_len"] = len(pkt[Raw].load)

    return info


def start_sniffing(on_packet):
    """
    Begin live packet capture. `on_packet` is a callback that receives
    the parsed dict for every IP packet seen.
    """
    iface_msg = config.INTERFACE if config.INTERFACE else "default interface"
    log_info(f"Starting live capture on {iface_msg}. Press Ctrl+C to stop.")

    def _handle(pkt):
        parsed = _parse_packet(pkt)
        if parsed:
            on_packet(parsed)

    sniff(iface=config.INTERFACE, prn=_handle, store=False)
