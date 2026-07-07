"""
logger.py
---------
Handles writing alerts to both the console (with color) and a persistent
log file, so you have evidence/history to show in your report or video.
"""

import os
import datetime
from config import LOG_FILE

# ANSI colors for console output (Windows 10+ terminals support this natively)
COLORS = {
    "LOW": "\033[93m",      # yellow
    "MEDIUM": "\033[38;5;208m",  # orange
    "HIGH": "\033[91m",     # red
    "RESET": "\033[0m",
}


def _ensure_log_dir():
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)


def log_alert(severity: str, category: str, src_ip: str, dst_ip: str, detail: str):
    """
    Write an alert to console (colorized) and to the log file (plain text).

    severity: "LOW" | "MEDIUM" | "HIGH"
    category: e.g. "PORT_SCAN", "SYN_FLOOD", "BLACKLIST", "SUSPICIOUS_PORT"
    """
    _ensure_log_dir()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    line = f"[{timestamp}] [{severity}] [{category}] {src_ip} -> {dst_ip} | {detail}"

    color = COLORS.get(severity, "")
    reset = COLORS["RESET"]
    print(f"{color}{line}{reset}")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def log_info(message: str):
    """Plain informational message (startup, shutdown, stats) - console only."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [INFO] {message}")
