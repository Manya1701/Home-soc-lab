# Home SOC Lab — Network Traffic Analyzer

A lightweight home security-operations-center project: sniffs live network
traffic, flags suspicious behavior (port scans, ICMP floods, traffic spikes)
using sliding-window detection logic, logs everything to CSV, and generates
a summary report with charts.

## Why this exists
Built as a hands-on way to understand basic intrusion-detection concepts —
what a port scan actually looks like on the wire, how to reason about
sliding time windows, and how to go from raw packets to actionable alerts.

## Project structure
```
home-soc-lab/
├── capture.py            # live capture (requires root + Scapy, Linux)
├── simulate_traffic.py   # generates synthetic traffic — no root needed
├── detectors.py          # PortScanDetector, IcmpFloodDetector, TrafficSpikeDetector
├── logger.py             # CSV logging for packets + alerts
├── report.py             # reads a session's logs, prints summary, saves charts
├── requirements.txt
└── logs/ , reports/      # created automatically when you run things
```

## Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Option A — Try it instantly, no root/network needed
This runs the exact same detection + logging pipeline as live capture, just
fed with synthetically crafted packets (normal traffic + a simulated port
scan + a simulated ICMP flood):

```bash
python3 simulate_traffic.py
python3 report.py
```

You'll see live `[ALERT]` lines print as the attacks are detected, then
`report.py` will print a summary and save charts to `reports/`.

## Option B — Real live capture (Linux, needs root)
```bash
sudo python3 capture.py --iface eth0 --duration 60
python3 report.py
```
Requires raw-socket access, so it must be run with `sudo`. Find your
interface name with `ip a` or `ifconfig`. Point a scanner (e.g. `nmap -sS`)
or a ping flood at a test machine on your own network to see it flag alerts
in real time — **only test against systems you own or have explicit
permission to test.**

## How detection works
Each detector keeps a per-source-IP sliding time window and looks for a
behavioral signature rather than a single "bad" packet:

- **PortScanDetector** — flags a source IP once it sends bare SYN packets
  (no ACK) to ≥15 distinct destination ports within a 10-second window.
  This is the classic signature of tools like `nmap -sS`.
- **IcmpFloodDetector** — flags a source IP once it sends ≥30 ICMP packets
  within a 5-second window (ping flood / ICMP sweep behavior).
- **TrafficSpikeDetector** — flags any source IP whose overall packet rate
  (any protocol) exceeds 100 packets within a 5-second window, as a
  catch-all for volumetric anomalies the other two might miss.

All thresholds are constructor arguments in `detectors.py` — tune them for
your own network's baseline noise level.

## Output
- `logs/packets_<session>.csv` — every packet seen, normalized
- `logs/alerts_<session>.csv` — every alert raised, with severity + detail
- `reports/traffic_by_protocol.png`
- `reports/top_talkers.png`
- `reports/alerts_timeline.png`

## Possible extensions
- Add a blacklist/allowlist of known-bad IPs (threat intel feed)
- Persist state across sessions instead of resetting each run
- Slack/email webhook on HIGH-severity alerts
- Swap CSV logging for SQLite for larger sessions
