import os
import json
import time
import glob
import logging
import subprocess
from collections import Counter
from threading import Thread
from rich.live import Live
from rich.table import Table
from rich.console import Console
import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
SYSLOG_FILE = os.path.join(BASE_DIR, "syslog.log")
LOG_FILE = os.path.join(BASE_DIR, "soc_monitor.log")

BAN_THRESHOLD = 10
WHITELIST_IPS = {"127.0.0.1", "192.168.1.1"}
POLL_INTERVAL = 5

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/your/slack/webhook"

console = Console()
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def log_and_print(level, message):
    print(message)
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)

def send_slack(message):
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json={"text": message})
        if resp.status_code == 200:
            log_and_print("info", "Sent Slack notification")
        else:
            log_and_print("error", f"Slack webhook error: {resp.status_code} {resp.text}")
    except Exception as e:
        log_and_print("error", f"Failed to send Slack message: {e}")

def block_ip(ip):
    if ip in WHITELIST_IPS:
        log_and_print("info", f"IP {ip} in whitelist, skipping block")
        return
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        log_and_print("warning", f"Blocked IP {ip} via iptables")
    except Exception as e:
        log_and_print("error", f"Failed to block IP {ip}: {e}")

def load_alerts():
    alerts = []
    pattern = os.path.join(ALERTS_DIR, "*.json")
    files = glob.glob(pattern)
    for filepath in files:
        if os.path.isdir(filepath):
            continue
        try:
            with open(filepath, "r") as f:
                alert = json.load(f)
                if isinstance(alert, dict):
                    alerts.append(alert)
        except Exception as e:
            log_and_print("error", f"Failed to load {filepath}: {e}")
    return alerts

def tail_syslog(file_path, callback):
    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            callback(line.strip())

def parse_syslog_line(line):
    import re
    m = re.search(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)', line)
    if m:
        ip = m.group(1)
        return {
            "ip": ip,
            "severity": "high",
            "threat_type": "failed_login",
            "description": "Failed SSH login attempt"
        }
    return None

def score_alert(alert):
    severity_map = {"low": 1, "medium": 5, "high": 10, "critical": 15}
    severity_raw = alert.get("severity", "low")
    try:
        severity = str(severity_raw).lower()
    except Exception:
        severity = "low"
    score = severity_map.get(severity, 0)

    ip = alert.get("ip")
    if ip and ip not in WHITELIST_IPS:
        score += 5

    threat = alert.get("threat_type", "")
    if isinstance(threat, str) and ("reverse_shell" in threat.lower() or "c2" in threat.lower()):
        score += 10

    return score

def process_alerts(alerts, ip_scores, ban_list):
    for alert in alerts:
        ip = alert.get("ip", "unknown")
        desc = alert.get("description", "No description")
        score = score_alert(alert)
        log_and_print("info", f"Alert: IP={ip}, Score={score}, Desc={desc}")

        if ip not in WHITELIST_IPS:
            ip_scores[ip] += score
            if ip_scores[ip] >= BAN_THRESHOLD and ip not in ban_list:
                ban_list.add(ip)
                message = f"IP {ip} exceeded ban threshold with score {ip_scores[ip]}"
                log_and_print("warning", message)
                send_slack(message)
                block_ip(ip)

def render_dashboard(ip_scores):
    table = Table(title="SOC Alert Monitor - IP Scores")
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Score", style="magenta")

    sorted_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)
    for ip, score in sorted_ips:
        table.add_row(ip, str(score))

    return table

def main():
    if not os.path.isdir(ALERTS_DIR):
        log_and_print("error", f"Alerts directory '{ALERTS_DIR}' does not exist.")
        return

    ip_scores = Counter()
    ban_list = set()

    if os.path.isfile(SYSLOG_FILE):
        def syslog_callback(line):
            alert = parse_syslog_line(line)
            if alert:
                process_alerts([alert], ip_scores, ban_list)

        t = Thread(target=tail_syslog, args=(SYSLOG_FILE, syslog_callback), daemon=True)
        t.start()
    else:
        log_and_print("warning", f"Syslog file '{SYSLOG_FILE}' not found, skipping syslog monitoring.")

    log_and_print("info", "SOC Alert Monitor started.")

    with Live(render_dashboard(ip_scores), refresh_per_second=1, console=console) as live:
        while True:
            alerts = load_alerts()
            if alerts:
                process_alerts(alerts, ip_scores, ban_list)
            else:
                log_and_print("info", "No alerts to process.")
            live.update(render_dashboard(ip_scores))
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
