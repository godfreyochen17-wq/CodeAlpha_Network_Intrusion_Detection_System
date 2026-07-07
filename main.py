"""
main.py
-------
Entry point for the Network Intrusion Detection System (NIDS).

Usage:
    python main.py                 -> live capture mode (needs admin/root + Npcap on Windows)
    python main.py --pcap file.pcap -> analyze a saved capture file instead of live traffic

This ties the sniffer (packet capture) to the detector (rule engine).
"""

import argparse
import sys

from detector import IntrusionDetector
from logger import log_info


def run_live():
    from sniffer import start_sniffing

    detector = IntrusionDetector()
    try:
        start_sniffing(on_packet=detector.process_packet)
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print("\nError starting packet capture. On Windows, make sure:")
        print("  1) Npcap is installed (https://npcap.com/)")
        print("  2) You are running this terminal as Administrator")
        print(f"\nOriginal error: {e}")
        sys.exit(1)
    finally:
        detector.print_summary()


def run_pcap(path: str):
    from scapy.all import rdpcap
    from sniffer import _parse_packet

    detector = IntrusionDetector()
    log_info(f"Reading packets from {path} ...")
    packets = rdpcap(path)
    for pkt in packets:
        parsed = _parse_packet(pkt)
        if parsed:
            detector.process_packet(parsed)
    detector.print_summary()


def main():
    parser = argparse.ArgumentParser(description="Simple Python Network Intrusion Detection System")
    parser.add_argument("--pcap", help="Path to a .pcap file to analyze instead of live capture", default=None)
    args = parser.parse_args()

    if args.pcap:
        run_pcap(args.pcap)
    else:
        run_live()


if __name__ == "__main__":
    main()
