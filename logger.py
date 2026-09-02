"""
logger.py
Lightweight CSV logging for packet events and alerts, so a session can be
analyzed later by report.py (or opened directly in Excel/Pandas).
"""

import csv
import os
import time


class SocLogger:
    def __init__(self, log_dir: str = "logs"):
        os.makedirs(log_dir, exist_ok=True)
        session_id = time.strftime("%Y%m%d_%H%M%S")
        self.packets_path = os.path.join(log_dir, f"packets_{session_id}.csv")
        self.alerts_path = os.path.join(log_dir, f"alerts_{session_id}.csv")

        self._packets_file = open(self.packets_path, "w", newline="")
        self._alerts_file = open(self.alerts_path, "w", newline="")

        self._packet_writer = csv.DictWriter(
            self._packets_file,
            fieldnames=["timestamp", "src_ip", "dst_ip", "proto", "dst_port", "flags", "length"],
        )
        self._alert_writer = csv.DictWriter(
            self._alerts_file,
            fieldnames=["timestamp", "type", "severity", "src_ip", "detail"],
        )
        self._packet_writer.writeheader()
        self._alert_writer.writeheader()

    def log_packet(self, event: dict):
        self._packet_writer.writerow(event)

    def log_alert(self, alert: dict):
        self._alert_writer.writerow(alert)
        # also print live to console so the analyst sees it in real time
        print(f"[ALERT] {alert['severity']:<6} {alert['type']:<14} "
              f"src={alert['src_ip']:<15} {alert['detail']}")

    def close(self):
        self._packets_file.close()
        self._alerts_file.close()
        print(f"\nSession logs saved:\n  {self.packets_path}\n  {self.alerts_path}")
