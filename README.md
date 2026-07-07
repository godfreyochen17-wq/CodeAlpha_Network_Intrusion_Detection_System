# CodeAlpha_Network_Intrusion_Detection_System

A lightweight, rule-based **Network Intrusion Detection System (NIDS)** built in Python using `scapy`.
Built as part of the **CodeAlpha Cyber Security Internship**.

## What it does

The program captures live network packets and analyzes them in real time against a set of
detection rules, raising alerts when suspicious patterns are seen:

| Detection Rule | Description |
|---|---|
| **Port Scan** | Flags a source IP that contacts many distinct destination ports in a short time window |
| **SYN Flood / DoS** | Flags a source IP sending an abnormally high rate of TCP SYN packets |
| **Repeated Connections** | Flags repeated connection attempts to the same port (possible brute force, e.g. SSH/RDP) |
| **Blacklisted IPs** | Flags any traffic to/from a configured list of known-bad IPs |
| **Suspicious Ports** | Flags connections to commonly-attacked ports (Telnet, RDP, SMB, etc.) |
| **Oversized Payloads** | Flags unusually large packet payloads (possible exfiltration/exploit attempt) |

All alerts are printed to the console (color-coded by severity) and written to `logs/alerts.log`.

## Project Structure

```
CodeAlpha_Network_Intrusion_Detection_System/
├── main.py              # Entry point - run this
├── sniffer.py           # Captures live packets via scapy
├── detector.py          # Rule engine - the core detection logic
├── config.py             # All thresholds, blacklist, ports - tune here
├── logger.py             # Console + file alert logging
├── simulate_attack.py    # Generates demo traffic to test detection
├── requirements.txt
├── logs/
│   └── alerts.log         # Generated at runtime
└── README.md
```

## Setup (Windows)

1. **Install Npcap** (required for scapy to capture packets on Windows):
   https://npcap.com/#download — during install, check "Install Npcap in WinPcap API-compatible Mode".

2. **Install Python dependencies:**
   ```
   pip install -r requirements.txt
   ```

3. **Run the NIDS** (must be run from an **Administrator** terminal/PowerShell):
   ```
   python main.py
   ```
   You should see:
   ```
   [INFO] Starting live capture on default interface. Press Ctrl+C to stop.
   ```

4. Browse the web, ping something, etc. — you'll see suspicious-port or other alerts appear
   naturally depending on your traffic.

## Demo: Triggering Detections On Purpose

Since you may not have a live attacker to demonstrate against, use the included simulator to
generate safe, self-contained "attack" traffic against your own machine (`127.0.0.1`):

1. In **Terminal 1** (as Administrator), start the NIDS:
   ```
   python main.py
   ```

2. In **Terminal 2**, run the simulator:
   ```
   python simulate_attack.py --both
   ```

3. Watch Terminal 1 — you should see `PORT_SCAN` and `SYN_FLOOD` alerts appear in real time,
   and get written to `logs/alerts.log`.

This gives you a clean, repeatable demo for your submission video.

## Analyzing a Saved Capture Instead of Live Traffic

If you'd rather analyze a `.pcap` file (e.g. downloaded sample malicious traffic, or one you
captured with Wireshark) instead of live traffic:

```
python main.py --pcap path\to\file.pcap
```

## Tuning Detection Sensitivity

All thresholds live in `config.py`:

```python
PORT_SCAN_THRESHOLD = 15     # distinct ports within PORT_SCAN_WINDOW seconds
SYN_FLOOD_THRESHOLD = 50     # SYN packets within SYN_FLOOD_WINDOW seconds
REPEAT_CONN_THRESHOLD = 20   # connections to same port within REPEAT_CONN_WINDOW seconds
```

Lower these values to make the demo trigger alerts faster/more easily.

## How It Works (for the video explanation)

1. `sniffer.py` uses `scapy.sniff()` to capture live packets and pulls out the fields that matter:
   source/destination IP, destination port, TCP flags, and payload size.
2. Each parsed packet is handed to `detector.py`, which maintains **sliding time windows**
   (using `collections.deque`) of recent activity per source IP.
3. On every packet, each rule checks whether the relevant window has crossed its threshold
   (e.g. "has this IP hit 15+ distinct ports in the last 10 seconds?").
4. If a rule triggers, `logger.py` prints a color-coded alert and appends it to `logs/alerts.log`,
   with a short cooldown so the same alert doesn't spam repeatedly.

## Disclaimer

This project is for educational purposes as part of the CodeAlpha internship. Only capture and
analyze traffic on networks/systems you own or have explicit permission to monitor.
