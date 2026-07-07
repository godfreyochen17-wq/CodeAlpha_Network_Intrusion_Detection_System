"""
dashboard.py
------------
A lightweight live web dashboard for the NIDS, built with Flask.

Run with:
    python main.py --dashboard

Then open http://127.0.0.1:5000 in your browser (it opens automatically).
The page polls the backend every second for new alerts and stats -
no page refresh needed, updates appear live while main.py is sniffing.
"""

import threading
import webbrowser

from flask import Flask, jsonify, render_template_string

import logger

app = Flask(__name__)

# Injected by main.py so the dashboard can read live packet/alert counts
_detector = None


def set_detector(detector):
    global _detector
    _detector = detector


INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NIDS Live Dashboard</title>
<style>
  :root {
    --bg: #0d1117;
    --panel: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --muted: #8b949e;
    --high: #f85149;
    --medium: #f0883e;
    --low: #e3b341;
    --accent: #58a6ff;
    --good: #3fb950;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Segoe UI', -apple-system, sans-serif;
    margin: 0;
    padding: 24px;
  }
  h1 {
    font-size: 20px;
    margin: 0 0 4px 0;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .pulse {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--good);
    box-shadow: 0 0 8px var(--good);
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse {
    0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; }
  }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 24px; }

  .stats {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 24px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }
  .card .value { font-size: 26px; font-weight: 600; }
  .card .label { font-size: 12px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .card.high .value { color: var(--high); }
  .card.medium .value { color: var(--medium); }
  .card.low .value { color: var(--low); }
  .card.packets .value { color: var(--accent); }

  table {
    width: 100%;
    border-collapse: collapse;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  th, td {
    padding: 10px 12px;
    text-align: left;
    font-size: 13px;
    border-bottom: 1px solid var(--border);
  }
  th {
    color: var(--muted);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.5px;
  }
  tr:last-child td { border-bottom: none; }
  tr.new-row { animation: flash 1.2s ease-out; }
  @keyframes flash {
    0% { background: rgba(88, 166, 255, 0.25); }
    100% { background: transparent; }
  }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge.HIGH { background: rgba(248,81,73,0.15); color: var(--high); }
  .badge.MEDIUM { background: rgba(240,136,62,0.15); color: var(--medium); }
  .badge.LOW { background: rgba(227,179,65,0.15); color: var(--low); }

  .empty {
    text-align: center;
    color: var(--muted);
    padding: 40px;
    font-size: 13px;
  }
</style>
</head>
<body>

  <h1><span class="pulse"></span> NIDS Live Dashboard</h1>
  <div class="subtitle">CodeAlpha Network Intrusion Detection System &mdash; auto-refreshes every second</div>

  <div class="stats">
    <div class="card packets"><div class="value" id="stat-packets">0</div><div class="label">Packets Processed</div></div>
    <div class="card"><div class="value" id="stat-total">0</div><div class="label">Total Alerts</div></div>
    <div class="card high"><div class="value" id="stat-high">0</div><div class="label">High</div></div>
    <div class="card medium"><div class="value" id="stat-medium">0</div><div class="label">Medium</div></div>
    <div class="card low"><div class="value" id="stat-low">0</div><div class="label">Low</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Time</th>
        <th>Severity</th>
        <th>Category</th>
        <th>Source IP</th>
        <th>Destination IP</th>
        <th>Detail</th>
      </tr>
    </thead>
    <tbody id="alert-body">
      <tr><td colspan="6" class="empty">Waiting for traffic&hellip;</td></tr>
    </tbody>
  </table>

<script>
let lastCount = 0;

async function refresh() {
  try {
    const [alertsRes, statsRes] = await Promise.all([
      fetch('/api/alerts'),
      fetch('/api/stats')
    ]);
    const alerts = await alertsRes.json();
    const stats = await statsRes.json();

    document.getElementById('stat-packets').textContent = stats.packets_processed ?? 0;
    document.getElementById('stat-total').textContent = stats.alerts_raised ?? 0;
    document.getElementById('stat-high').textContent = stats.severity_counts?.HIGH ?? 0;
    document.getElementById('stat-medium').textContent = stats.severity_counts?.MEDIUM ?? 0;
    document.getElementById('stat-low').textContent = stats.severity_counts?.LOW ?? 0;

    const body = document.getElementById('alert-body');
    if (alerts.length === 0) {
      body.innerHTML = '<tr><td colspan="6" class="empty">Waiting for traffic&hellip;</td></tr>';
      lastCount = 0;
      return;
    }

    // Show newest first
    const reversed = [...alerts].reverse();
    body.innerHTML = reversed.map((a, i) => `
      <tr class="${i < (alerts.length - lastCount) ? 'new-row' : ''}">
        <td>${a.timestamp}</td>
        <td><span class="badge ${a.severity}">${a.severity}</span></td>
        <td>${a.category}</td>
        <td>${a.src_ip}</td>
        <td>${a.dst_ip}</td>
        <td>${a.detail}</td>
      </tr>
    `).join('');

    lastCount = alerts.length;
  } catch (err) {
    console.error('Dashboard refresh failed:', err);
  }
}

refresh();
setInterval(refresh, 1000);
</script>

</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/api/alerts")
def api_alerts():
    with logger._history_lock:
        alerts = list(logger.ALERT_HISTORY[-200:])  # cap for performance
    return jsonify(alerts)


@app.route("/api/stats")
def api_stats():
    stats = dict(_detector.stats) if _detector else {"packets_processed": 0, "alerts_raised": 0}

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    with logger._history_lock:
        for a in logger.ALERT_HISTORY:
            if a["severity"] in severity_counts:
                severity_counts[a["severity"]] += 1

    stats["severity_counts"] = severity_counts
    return jsonify(stats)


def run_dashboard(detector, host="127.0.0.1", port=5000, open_browser=True):
    """Starts the Flask dashboard. Intended to be run in a background thread
    from main.py while the sniffer runs on the main thread."""
    set_detector(detector)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{host}:{port}")).start()
    app.run(host=host, port=port, debug=False, use_reloader=False)
