#!/usr/bin/env python3
# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - Anomaly Detection Daemon
# ==============================================================================
# Description: Tails the Wazuh alerts log file, extracts event parameters,
#              evaluates them via the trained Isolation Forest ML model,
#              and dispatches alarms for detected outliers.
# ==============================================================================

import os
import sys
import json
import time
import pickle
import datetime
# pyrefly: ignore [missing-import]
import numpy as np
from collections import defaultdict

# Setup paths
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(CURRENT_DIR))
sys.path.append(PROJECT_ROOT)

from scripts.alerts.alert_manager import AlertManager

MODEL_DIR = os.path.join(CURRENT_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

# Fallback path for alerts log
LOG_FILE_PATH = os.environ.get("LOG_FILE_PATH", "/var/ossec/logs/alerts/alerts.json")
ALERTS_JSON_PATH = os.environ.get("ALERTS_JSON_PATH", os.path.join(PROJECT_ROOT, "reports", "alerts.json"))

class AnomalyEngine:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.alert_manager = AlertManager()
        self.failed_logins = defaultdict(list) # Stores timestamps of failed logins per IP
        
        self.load_model()

    def load_model(self):
        """Loads or auto-trains the ML classifier."""
        if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
            print("[!] Model files not found. Auto-training baseline models...")
            # Auto-run training script inline
            from scripts.ai_detection.train_baseline import train_and_save
            train_and_save()

        with open(MODEL_PATH, 'rb') as f:
            self.model = pickle.load(f)
        with open(SCALER_PATH, 'rb') as f:
            self.scaler = pickle.load(f)
        print("[*] Anomaly detection model and scaler loaded successfully.")

    def clean_old_failed_logins(self, timeframe_seconds=300):
        """Removes failed login records older than 5 minutes."""
        now = time.time()
        for ip in list(self.failed_logins.keys()):
            self.failed_logins[ip] = [t for t in self.failed_logins[ip] if now - t < timeframe_seconds]
            if not self.failed_logins[ip]:
                del self.failed_logins[ip]

    def extract_features(self, alert):
        """
        Parses Wazuh JSON log file to extract ML feature variables:
        [login_hour, login_duration, failed_attempts, data_transmitted, cpu_utilization, ram_utilization]
        """
        # Feature defaults representing median normal operations
        login_hour = 12.0
        login_duration = 60.0
        failed_attempts = 0
        data_transmitted = 100.0 # KB
        cpu_utilization = 15.0
        ram_utilization = 40.0
        
        # 1. Parse hour from event timestamp
        timestamp_str = alert.get("timestamp", "")
        if timestamp_str:
            try:
                # Format: 2026-06-02T20:45:00.000+0000 or similar
                dt = datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00").split(".")[0])
                login_hour = float(dt.hour)
            except Exception:
                pass
                
        # 2. Extract rule & source variables
        rule = alert.get("rule", {})
        rule_id = int(rule.get("id", 0))
        src_ip = alert.get("data", {}).get("srcip", alert.get("srcip", "0.0.0.0"))
        
        # Track moving fail counts
        if rule_id in [5716, 5722, 5760, 5763, 100001, 100002]: # failed logins sids
            self.failed_logins[src_ip].append(time.time())
            
        self.clean_old_failed_logins()
        failed_attempts = len(self.failed_logins[src_ip])
        
        # 3. Extract resource telemetry if system metric event
        # E.g. parsed via custom metrics rules
        metrics = alert.get("data", {})
        if "cpu_utilization" in metrics:
            cpu_utilization = float(metrics["cpu_utilization"])
        if "ram_utilization" in metrics:
            ram_utilization = float(metrics["ram_utilization"])
        
        # Fallback to decode from custom‑metrics-fields status & extra_data
        status = metrics.get("status", "")
        extra_data = metrics.get("extra_data", "")
        if status == "CPU_ALERT" and extra_data:
            try:
                cpu_utilization = float(extra_data.replace("%", ""))
            except Exception:
                pass
        elif status == "RAM_ALERT" and extra_data:
            try:
                ram_utilization = float(extra_data.replace("%", ""))
            except Exception:
                pass

        if "bytes" in metrics:
            data_transmitted = float(metrics["bytes"]) / 1024.0 # Convert to KB
            
        return [login_hour, login_duration, failed_attempts, data_transmitted, cpu_utilization, ram_utilization]

    def analyze_event(self, alert):
        """Runs the Isolation Forest evaluation on the alert features, with a rule‑based fallback for clear anomalies."""
        features = self.extract_features(alert)
        feature_vector = np.array([features])
        
        # Transform features
        scaled_features = self.scaler.transform(feature_vector)
        
        # Rule‑based quick check: if failed attempts >= 10 or CPU/RAM > 90% treat as anomaly
        failed_attempts = features[2]
        cpu_util = features[4]
        ram_util = features[5]
        if failed_attempts >= 10 or cpu_util > 90 or ram_util > 90:
            prediction = -1
            score = -0.1  # dummy low score to indicate anomaly
        else:
            # Predict via Isolation Forest
            prediction = self.model.predict(scaled_features)[0]
            score = self.model.decision_function(scaled_features)[0]
        
        print(f"DEBUG: features={features} -> score={score:.4f}, prediction={prediction}")
        
        if prediction == -1:
            # Trigger Anomaly Alert
            rule_desc = alert.get("rule", {}).get("description", "Unknown log event")
            src_ip = alert.get("data", {}).get("srcip", alert.get("srcip", "Unknown IP"))
            agent_name = alert.get("agent", {}).get("name", "SIEM-Manager")
            timestamp = alert.get("timestamp", datetime.datetime.utcnow().isoformat() + "Z")
            
            print(f"[!] ANOMALY DETECTED | Score: {score:.4f} | Agent: {agent_name} | IP: {src_ip} | Base Event: {rule_desc}")
            
            anomaly_details = {
                "score": float(score),
                "timestamp": timestamp,
                "source_ip": src_ip,
                "agent": agent_name,
                "base_rule_description": rule_desc,
                "extracted_features": {
                    "login_hour": features[0],
                    "login_duration": features[1],
                    "failed_attempts_5m": features[2],
                    "data_transmitted_kb": features[3],
                    "cpu_utilization": features[4],
                    "ram_utilization": features[5]
                }
            }
            
            # Send alert to AlertManager channels
            self.alert_manager.dispatch_anomaly_alert(anomaly_details)

            # Format and write AI Anomaly Alert to the Dashboard JSON
            alert_item = {
                "severity": "critical" if score < -0.15 else "high",
                "agent": agent_name,
                "ip": src_ip,
                "event": f"AI ANOMALY: {rule_desc}",
                "timestamp": timestamp,
                "anomaly_score": float(score),
                "features": anomaly_details["extracted_features"]
            }
            self.write_alert_to_dashboard(alert_item)

        else:
            rule = alert.get("rule", {})
            rule_level = int(rule.get("level", 0))
            if rule_level >= 8:
                rule_desc = rule.get("description", "Unknown log event")
                src_ip = alert.get("data", {}).get("srcip", alert.get("srcip", "Unknown IP"))
                agent_name = alert.get("agent", {}).get("name", "SIEM-Manager")
                timestamp = alert.get("timestamp", datetime.datetime.utcnow().isoformat() + "Z")
                
                print(f"[*] Ingesting High-Level Alert | Level: {rule_level} | Agent: {agent_name} | IP: {src_ip} | Event: {rule_desc}")
                
                # Format and write High Severity Alert to the Dashboard JSON
                alert_item = {
                    "severity": "critical" if rule_level >= 12 else "high",
                    "agent": agent_name,
                    "ip": src_ip,
                    "event": rule_desc,
                    "timestamp": timestamp,
                    "rule_level": rule_level
                }
                self.write_alert_to_dashboard(alert_item)

    def write_alert_to_dashboard(self, alert_item):
        """Appends alert to the dashboard JSON file atomically, capping historical count to 100."""
        try:
            os.makedirs(os.path.dirname(ALERTS_JSON_PATH), exist_ok=True)
            alerts_list = []
            if os.path.exists(ALERTS_JSON_PATH):
                try:
                    with open(ALERTS_JSON_PATH, 'r') as f:
                        alerts_list = json.load(f)
                        if not isinstance(alerts_list, list):
                            alerts_list = []
                except Exception:
                    alerts_list = []
            
            # Prepend new alert (newest first)
            alerts_list.insert(0, alert_item)
            # Cap at 100 entries
            alerts_list = alerts_list[:100]
            
            # Atomic write
            temp_path = ALERTS_JSON_PATH + ".tmp"
            with open(temp_path, 'w') as f:
                json.dump(alerts_list, f, indent=2)
            os.replace(temp_path, ALERTS_JSON_PATH)
        except Exception as e:
            print(f"[ERR] Failed to write alert to dashboard file: {e}")

    def tail_log_file(self):
        """Continuously tails the logs output path in real-time."""
        print(f"[*] Starting log tailing on target: {LOG_FILE_PATH}")
        
        # Fallback simulation if running in offline mode/file doesn't exist
        if not os.path.exists(LOG_FILE_PATH):
            print(f"[!] Path {LOG_FILE_PATH} not found. Running simulation mode.")
            self.run_simulation_mode()
            return

        with open(LOG_FILE_PATH, 'r') as f:
            # Go to the end of the file
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    alert = json.loads(line)
                    self.analyze_event(alert)
                except Exception as e:
                    print(f"[ERR] Error parsing log line: {e}")

    def run_simulation_mode(self):
        """Simulates continuous log events to test model evaluations in isolated settings."""
        print("[*] Anomaly Engine simulation running. Press Ctrl+C to terminate.")
        # Simulating standard logins and then injecting anomalies
        normal_count = 0
        while True:
            time.sleep(2)
            normal_count += 1
            
            # Simulate logs: 90% normal, 10% anomaly
            is_anomaly = (normal_count % 8 == 0)
            
            if is_anomaly:
                mock_alert = {
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "agent": {"name": "Ubuntu-Production-Target"},
                    "rule": {"id": 5716, "description": "sshd: Authentication failed from IP"},
                    "srcip": "185.190.140.20",
                    "data": {
                        "cpu_utilization": 98.2,
                        "ram_utilization": 91.5,
                        "bytes": 52428800 # 50 MB
                    }
                }
                # Inject multiple failed attempts into tracking dictionary
                for _ in range(12):
                    self.failed_logins["185.190.140.20"].append(time.time())
            else:
                # Normal business hour access
                mock_alert = {
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "agent": {"name": "Ubuntu-Production-Target"},
                    "rule": {"id": 5715, "description": "sshd: Successful login"},
                    "srcip": "192.168.1.15",
                    "data": {
                        "cpu_utilization": 12.5,
                        "ram_utilization": 38.0,
                        "bytes": 2048 # 2 KB
                    }
                }
                
            self.analyze_event(mock_alert)

if __name__ == '__main__':
    try:
        engine = AnomalyEngine()
        engine.tail_log_file()
    except KeyboardInterrupt:
        print("\n[+] Shutting down anomaly detection engine daemon.")
        sys.exit(0)
