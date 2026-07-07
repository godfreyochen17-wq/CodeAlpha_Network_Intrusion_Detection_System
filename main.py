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
import time

from detector import IntrusionDetector
from logger import log_info


def _maybe_start_dashboard(detector, enable_dashboard: bool):
    if not enable_dashboard:
        return
    import threading
    from dashboard import run_dashboard

    t = threading.Thread(target=run_dashboard, args=(detector,), daemon=True)
    t.start()
    log_info("Live dashboard starting at http://127.0.0.1:5000 (opening browser...)")


def run_live(enable_dashboard: bool = False):
    from sniffer import start_sniffing

    detector = IntrusionDetector()
    _maybe_start_dashboard(detector, enable_dashboard)

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


def run_pcap(path: str, enable_dashboard: bool = False):
    from scapy.all import rdpcap
    from sniffer import _parse_packet

    detector = IntrusionDetector()
    _maybe_start_dashboard(detector, enable_dashboard)

    log_info(f"Reading packets from {path} ...")
    packets = rdpcap(path)
    for pkt in packets:
        parsed = _parse_packet(pkt)
        if parsed:
            detector.process_packet(parsed)
    detector.print_summary()

    if enable_dashboard:
        log_info("Dashboard still running - press Ctrl+C to exit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


def main():
    parser = argparse.ArgumentParser(description="Simple Python Network Intrusion Detection System")
    parser.add_argument("--pcap", help="Path to a .pcap file to analyze instead of live capture", default=None)
    parser.add_argument("--dashboard", action="store_true", help="Launch the live web dashboard at http://127.0.0.1:5000")
    args = parser.parse_args()

    if args.pcap:
        run_pcap(args.pcap, enable_dashboard=args.dashboard)
    else:
        run_live(enable_dashboard=args.dashboard)


if __name__ == "__main__":
    main()
