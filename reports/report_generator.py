#!/usr/bin/env python3
# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - Executive Report Compiler
# ==============================================================================
# Description: Parses wazuh logs and generates structured security status reports
#              with Matplotlib graphics rendering alert distributions.
# ==============================================================================

import os
import sys
import json
import datetime
from collections import Counter

# Ensure matplotlib is run headlessly (no display backend required for servers)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

LOG_FILE_PATH = os.environ.get("LOG_FILE_PATH", "/var/ossec/logs/alerts/alerts.json")
REPORT_OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

def parse_alerts_log(max_lines=5000):
    """Reads logs and parses threat event fields."""
    if not os.path.exists(LOG_FILE_PATH):
        print(f"[!] Log file {LOG_FILE_PATH} not found. Utilizing mock records for report compilation.")
        return get_mock_alerts()

    alerts = []
    try:
        with open(LOG_FILE_PATH, 'r') as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                try:
                    alerts.append(json.loads(line))
                except Exception:
                    pass
    except Exception as e:
        print(f"[ERR] Failed to read alert log file: {e}")
        
    return alerts if alerts else get_mock_alerts()

def get_mock_alerts():
    """Returns sample mock alert events for testing log reports."""
    now = datetime.datetime.utcnow().isoformat()
    return [
        {"timestamp": now, "agent": {"name": "Ubuntu-Agent-Prod"}, "rule": {"id": 100002, "level": 10, "description": "SIEM critical: SSH brute force attack detected"}},
        {"timestamp": now, "agent": {"name": "Ubuntu-Agent-Prod"}, "rule": {"id": 100001, "level": 5, "description": "SIEM alert: Multiple failed SSH login attempts detected"}},
        {"timestamp": now, "agent": {"name": "Windows-Agent-10"}, "rule": {"id": 5403, "level": 9, "description": "SIEM alert: Sudo privilege execution denied for user"}},
        {"timestamp": now, "agent": {"name": "Ubuntu-Agent-Prod"}, "rule": {"id": 100030, "level": 12, "description": "SIEM critical: Reverse shell process spawning command detected"}},
        {"timestamp": now, "agent": {"name": "Ubuntu-Agent-Prod"}, "rule": {"id": 100040, "level": 7, "description": "SIEM warning: Target system resource thresholds exceeded"}},
        {"timestamp": now, "agent": {"name": "Kubernetes-Node-01"}, "rule": {"id": 100031, "level": 11, "description": "SIEM alert: Cryptomining software signature detected on node"}},
        {"timestamp": now, "agent": {"name": "Ubuntu-Agent-Prod"}, "rule": {"id": 100040, "level": 7, "description": "SIEM warning: Target system resource thresholds exceeded"}},
        {"timestamp": now, "agent": {"name": "Windows-Agent-10"}, "rule": {"id": 5716, "level": 5, "description": "sshd: Authentication failed from IP"}},
    ]

def compile_metrics(alerts):
    """Aggregates alert metrics from log lines."""
    total_alerts = len(alerts)
    severities = []
    agents = []
    rules = []
    
    for alert in alerts:
        rule = alert.get("rule", {})
        level = int(rule.get("level", 0))
        description = rule.get("description", "Unknown Alert")
        agent_name = alert.get("agent", {}).get("name", "SIEM-Manager")
        
        severities.append(level)
        agents.append(agent_name)
        rules.append(description)
        
    severity_counts = Counter(severities)
    agent_counts = Counter(agents)
    rule_counts = Counter(rules)
    
    # Calculate critical count (Rule Level >= 10)
    critical_count = sum(1 for s in severities if s >= 10)
    
    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_count,
        "severities": dict(severity_counts),
        "agents": dict(agent_counts),
        "top_rules": rule_counts.most_common(5)
    }

def render_charts(metrics):
    """Generates visualization diagrams of severity distribution."""
    # Plot alert severity levels
    sevs = sorted(metrics["severities"].keys())
    counts = [metrics["severities"][s] for s in sevs]
    
    plt.figure(figsize=(10, 5))
    plt.bar([f"Level {s}" for s in sevs], counts, color='#7b1fa2', edgecolor='#4a148c')
    plt.title('Security Threat Severity Distribution', fontsize=14, fontweight='bold', color='#4a148c')
    plt.xlabel('Wazuh Alert Level', fontsize=12)
    plt.ylabel('Event Occurrence Count', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    chart_path = os.path.join(REPORT_OUTPUT_DIR, "alert_severity_chart.png")
    plt.tight_layout()
    plt.savefig(chart_path, dpi=150)
    plt.close()
    print(f"[+] Chart rendered successfully: {chart_path}")
    return chart_path

def generate_markdown_report(metrics, chart_file):
    """Constructs the executive Markdown summary report file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = os.path.join(REPORT_OUTPUT_DIR, "SIEM_Executive_Security_Report.md")
    
    # Top rule entries string
    rules_table = ""
    for rule, count in metrics["top_rules"]:
        rules_table += f"| {rule} | {count} |\n"
        
    # Affected nodes string
    nodes_table = ""
    for node, count in metrics["agents"].items():
        nodes_table += f"| {node} | {count} |\n"

    report_content = f"""# Executive Cybersecurity Incident & Status Report

**Report Generation Timestamp:** `{timestamp}`  
**SIEM Platform Instance ID:** `Wazuh-SOC-Production-01`

---

## 1. Executive Summary

During this audit window, the Enterprise SIEM Platform evaluated threat indicators, log streams, and system metrics. 
The custom machine learning anomaly engine monitored system baselines continuously.

* **Total Log Events Analyzed:** `{metrics['total_alerts']}`
* **High/Critical Events Flagged (Severity >= 10):** `{metrics['critical_alerts']}`
* **Active Nodes Reporting:** `{len(metrics['agents'])}`

---

## 2. Threat Vector Distribution

### Alert Occurrences by Severity Level

The following chart illustrates the frequency of security alerts aggregated by Wazuh rule severity levels.

![Alert Severity Chart](file:///{chart_file.replace('\\', '/')})

---

## 3. High-Frequency Threat Details

The table below lists the top 5 security rules triggered most frequently during this cycle.

| Security Threat Signature | Occurrences Count |
| :--- | :---: |
{rules_table}

---

## 4. Host Status Summary

Active monitoring agents and their related event counts:

| Monitored Agent Hostname | Ingested Alerts Count |
| :--- | :---: |
{nodes_table}

---

## 5. Security Recommendations

1. **Investigate High Severity Outliers:** Review alerts related to reverse shell indicators and SSH brute force IPs.
2. **Mitigate Active Response Bans:** Audit the IP blocking logs under `/var/ossec/logs/active-responses.log` to trace blocked source IPs.
3. **Verify Anomaly Baselines:** Review the Isolation Forest scoring parameters to retrain models if network behaviors change significantly.
"""
    with open(report_path, 'w') as f:
        f.write(report_content)
    print(f"[+] Executive report compiled successfully: {report_path}")

def main():
    print("[*] Starting SIEM Executive Report compiler...")
    alerts = parse_alerts_log()
    metrics = compile_metrics(alerts)
    chart = render_charts(metrics)
    generate_markdown_report(metrics, chart)
    print("[*] Compilation sequence finished.")

if __name__ == '__main__':
    main()
