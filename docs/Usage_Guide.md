# SIEM Platform Operations & Usage Guide

This document outlines the standard operating procedures for running the AI detection daemon, executing simulated attack vectors, compiling PDF/Markdown executive reports, and customizing dashboards.

---

## 1. Running the Anomaly Detection Daemon

The custom AI engine runs automatically inside the `siem-ai-engine` Docker container. However, during development, testing, or when running in offline modes, you can execute it manually.

### Install Local Python Dependencies
```bash
pip install -r requirements.txt
```

### Train the Baseline Model
Generate the initial normal behavioral profile and compile the Isolation Forest classifier:
```bash
python scripts/ai_detection/train_baseline.py
```
This action serializes `isolation_forest.pkl` and `scaler.pkl` within the `scripts/ai_detection/models/` directory.

### Launch Anomaly Engine Daemon
Run the real-time log parsing loop:
```bash
python scripts/ai_detection/anomaly_engine.py
```
If the Wazuh manager log file `/var/ossec/logs/alerts/alerts.json` does not exist locally, the daemon will automatically activate a mock alert generator simulation mode to demonstrate prediction pipelines.

---

## 2. Launching Threat Simulations

The simulation suite allows testing of decoders and active response triggers. Perform these steps from a target agent machine or the Kali Linux attacker node.

### Run Attack Menu Selector
```bash
chmod +x attack_simulation/simulate_attacks.sh
./attack_simulation/simulate_attacks.sh
```

### Simulation Menu Options

```text
================================================================
           SIEM Threat Detection Attack Simulation Lab          
================================================================
[!] WARNING: Run this simulator in sandbox environments ONLY.
----------------------------------------------------------------
1) Simulate SSH Brute Force
2) Simulate Reconnaissance Port Scan (Nmap-like)
3) Simulate Privilege Escalation (Sudo/Su misuse)
4) Simulate Reverse Shell Execution Fingerprint
5) Run All Simulation Vectors
6) Exit Lab
```

* **Option 1 (SSH Brute Force):** Requests a target IP and opens socket pipelines to simulate failed login credentials.
* **Option 2 (Port Scan):** Scans selected target port ranges to trigger firewall parsing decoders.
* **Option 3 (Privilege Escalation):** Simulates unauthorized root access checks, su execution errors, and file reading actions.
* **Option 4 (Reverse Shell):** Emulates reverse shell command strings to generate detection triggers.

---

## 3. Generating Security Executive Reports

The reporting engine translates raw alert logs into executive reports with visualizations.

### Run Report Generation Script
```bash
python reports/report_generator.py
```

### Output Artifacts
The script writes two files inside the `reports/` directory:
1. **`alert_severity_chart.png`:** Matplotlib bar chart showing threat volumes grouped by Wazuh rules levels.
2. **`SIEM_Executive_Security_Report.md`:** Markdown document linking the bar chart and summarizing threat statistics.

---

## 4. Visualizing Dashboard Metrics

To inspect active telemetry in the web interface:
1. Open the Wazuh dashboard Web console.
2. Select **Wazuh** -> **Security Events** -> **Dashboard**.
3. To load the custom SOC dashboard configuration, navigate to **Management** -> **Saved Objects** inside the Kibana sidebar, click **Import**, and select the [soc_dashboard.json](file:///c:/Users/appal/OneDrive/Attachments/Desktop/adobe/dashboards/soc_dashboard.json) file.
4. Interact with the imported widgets to trace alert distributions, search logged logs, and inspect AI-flagged outlier scores.
