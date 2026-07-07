"""
simulate_attack.py
-------------------
FOR DEMO / TESTING PURPOSES ONLY.

Generates traffic against 127.0.0.1 (your own machine) so you can show
main.py detecting a "port scan" and "SYN flood" live, without needing
a real attacker or a VM lab.

IMPORTANT:
- Only ever run this against 127.0.0.1 / a machine you own.
- Run `python main.py` in one terminal FIRST (as Administrator), then
  run this script in a second terminal to generate the traffic.

Usage:
    python simulate_attack.py --scan       -> simulate a port scan
    python simulate_attack.py --flood      -> simulate a SYN flood
    python simulate_attack.py --both       -> run both, one after another
"""

import argparse
import time
from scapy.all import IP, TCP, send

TARGET = "127.0.0.1"


def simulate_port_scan(target=TARGET, num_ports=30):
    print(f"[SIM] Simulating port scan against {target} ({num_ports} ports)...")
    for port in range(1, num_ports + 1):
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)
    print("[SIM] Port scan simulation complete.")


def simulate_syn_flood(target=TARGET, num_packets=80):
    print(f"[SIM] Simulating SYN flood against {target} ({num_packets} packets)...")
    for _ in range(num_packets):
        pkt = IP(dst=target) / TCP(dport=80, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.02)
    print("[SIM] SYN flood simulation complete.")


def main():
    parser = argparse.ArgumentParser(description="Generate demo traffic for the NIDS to detect")
    parser.add_argument("--scan", action="store_true", help="Simulate a port scan")
    parser.add_argument("--flood", action="store_true", help="Simulate a SYN flood")
    parser.add_argument("--both", action="store_true", help="Run both simulations")
    args = parser.parse_args()

    if args.both or (not args.scan and not args.flood):
        simulate_port_scan()
        time.sleep(1)
        simulate_syn_flood()
    else:
        if args.scan:
            simulate_port_scan()
        if args.flood:
            simulate_syn_flood()


if __name__ == "__main__":
    main()
