"""
report.py
Reads the most recent (or a specified) session's packet/alert CSV logs and
produces:
  - a printed text summary
  - traffic_by_protocol.png
  - top_talkers.png
  - alerts_timeline.png

Run: python3 report.py                     # uses most recent session in logs/
     python3 report.py --session 20260901_120000
"""

import argparse
import glob
import os

import matplotlib
matplotlib.use("Agg")  # headless-safe backend
import matplotlib.pyplot as plt
import pandas as pd


def find_latest_session(log_dir="logs"):
    packet_files = sorted(glob.glob(os.path.join(log_dir, "packets_*.csv")))
    if not packet_files:
        raise FileNotFoundError(
            "No session logs found. Run simulate_traffic.py or capture.py first."
        )
    latest = packet_files[-1]
    session_id = os.path.basename(latest).replace("packets_", "").replace(".csv", "")
    return session_id


def load_session(session_id, log_dir="logs"):
    packets_path = os.path.join(log_dir, f"packets_{session_id}.csv")
    alerts_path = os.path.join(log_dir, f"alerts_{session_id}.csv")
    packets_df = pd.read_csv(packets_path)
    alerts_df = pd.read_csv(alerts_path)
    return packets_df, alerts_df


def print_summary(packets_df, alerts_df):
    print("=" * 60)
    print("HOME SOC LAB — SESSION SUMMARY")
    print("=" * 60)
    print(f"Total packets captured : {len(packets_df)}")
    print(f"Unique source IPs      : {packets_df['src_ip'].nunique()}")
    print(f"Total alerts raised    : {len(alerts_df)}")
    if not alerts_df.empty:
        print("\nAlerts by type:")
        print(alerts_df["type"].value_counts().to_string())
        print("\nAlerts by source IP:")
        print(alerts_df["src_ip"].value_counts().to_string())
    print("=" * 60)


def plot_traffic_by_protocol(packets_df, out_dir):
    counts = packets_df["proto"].value_counts()
    plt.figure(figsize=(6, 4))
    counts.plot(kind="bar", color="#1F3864")
    plt.title("Traffic by Protocol")
    plt.ylabel("Packet count")
    plt.tight_layout()
    path = os.path.join(out_dir, "traffic_by_protocol.png")
    plt.savefig(path)
    plt.close()
    return path


def plot_top_talkers(packets_df, out_dir, top_n=10):
    counts = packets_df["src_ip"].value_counts().head(top_n)
    plt.figure(figsize=(7, 4))
    counts.plot(kind="barh", color="#2E75B6")
    plt.title(f"Top {top_n} Talkers (by packet count)")
    plt.xlabel("Packet count")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    path = os.path.join(out_dir, "top_talkers.png")
    plt.savefig(path)
    plt.close()
    return path


def plot_alerts_timeline(alerts_df, out_dir):
    if alerts_df.empty:
        return None
    plt.figure(figsize=(7, 4))
    colors = {"HIGH": "#C00000", "MEDIUM": "#ED7D31", "LOW": "#70AD47"}
    for severity, group in alerts_df.groupby("severity"):
        plt.scatter(group["timestamp"], [severity] * len(group),
                    color=colors.get(severity, "gray"), label=severity, s=60)
    plt.title("Alerts Timeline by Severity")
    plt.xlabel("Timestamp (unix)")
    plt.tight_layout()
    path = os.path.join(out_dir, "alerts_timeline.png")
    plt.savefig(path)
    plt.close()
    return path


def main():
    parser = argparse.ArgumentParser(description="Home SOC Lab - report generator")
    parser.add_argument("--session", default=None, help="Session id, e.g. 20260901_120000")
    parser.add_argument("--log-dir", default="logs")
    parser.add_argument("--out-dir", default="reports")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    session_id = args.session or find_latest_session(args.log_dir)
    print(f"Loading session: {session_id}\n")

    packets_df, alerts_df = load_session(session_id, args.log_dir)
    print_summary(packets_df, alerts_df)

    p1 = plot_traffic_by_protocol(packets_df, args.out_dir)
    p2 = plot_top_talkers(packets_df, args.out_dir)
    p3 = plot_alerts_timeline(alerts_df, args.out_dir)

    print("\nCharts saved:")
    for p in (p1, p2, p3):
        if p:
            print(f"  {p}")


if __name__ == "__main__":
    main()
