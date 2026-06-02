# System Architecture Documentation

This document describes the technical architecture, data pipelines, container configuration, and machine learning components of the SIEM platform.

---

## 1. Complete Ingestion & Processing Pipeline

Security logs trace the following workflow:

```text
+-------------------+      +-------------------+      +-------------------+
| Linux Agent Host  |      | Windows Agent Host|      | AWS Cloud Sources |
| - /var/log/auth   |      | - Security Event  |      | - GuardDuty       |
| - sudo/cron logs  |      | - PowerShell log  |      | - CloudTrail      |
+---------+---------+      +---------+---------+      +---------+---------+
          |                          |                          |
          | (Wazuh Protocol: 1514)   | (Wazuh Protocol: 1514)   | (Syslog UDP: 514)
          v                          v                          v
+-------------------------------------------------------------------------+
|                              Wazuh Manager                              |
| - Decodes raw logs using regex matches (custom_decoders.xml)            |
| - Correlates events against rulesets (custom_rules.xml)                 |
| - Evaluates triggers for Active Response script commands                |
| - Writes unified structured outputs to: /var/ossec/logs/alerts/alerts.json|
+------------------------------------+------------------------------------+
                                     |
                                     | (Alerts volume mounted)
                                     v
                  +------------------+------------------+
                  |                                     |
                  | (Shipped via Filebeat)              | (Read by python daemon)
                  v                                     v
+-----------------+-----------------+  +-----------------+-----------------+
|   Elasticsearch / Indexer Cluster |  |         siem-ai-engine          |
| - Indexes alerts into daily indices|  | - Parses features real-time       |
| - Stores telemetry data securely  |  | - Scores Isolation Forest model   |
+-----------------+-----------------+  | - Routes alerts to Telegram/Slack|
                  |                    +-----------------------------------+
                  | (REST HTTPS API)
                  v
+-----------------+-----------------+
|    Kibana / Wazuh Dashboard UI    |
| - Displays security analytics     |
| - Admin queries and configurations|
+-----------------------------------+
```

---

## 2. Platform Core Services Directory

The deployment is managed via a single `docker-compose.yml` deploying six connected services:

* **Wazuh Indexer (Elasticsearch):** A distributed, highly performant search and analytics indexer. Stores security alert logs, system metrics, and connection timelines.
* **Wazuh Manager:** The brain of the SIEM. Receives encrypted log streams from enrolled agents, matches signatures, decodes JSON events, and writes aggregated logs.
* **Wazuh Filebeat:** Runs alongside the manager container, tailing `/var/ossec/logs/alerts/alerts.json` and shipping records to the Indexer.
* **Wazuh Dashboard (Kibana):** Web UI dashboard containing query templates and tools for threat hunting.
* **Logstash:** Syslog ingestion gateway. Collects external logs, applies filters, and routes records to Elasticsearch.
* **SIEM AI Engine:** Local custom Python container running the ML outlier detector.

---

## 3. Python AI Anomaly Pipeline Details

The AI engine extracts a feature vector $X$ from ingested security events:

$$X = [x_1, x_2, x_3, x_4, x_5, x_6]$$

| Feature | Variable Definition | Ingestion Source | Normal Baseline Range |
| :--- | :--- | :--- | :---: |
| $x_1$ | **Login Time Hour** | Hour parsed from timestamp | `8.0` to `18.0` (8 AM - 6 PM) |
| $x_2$ | **Login Session Duration** | Minutes elapsed (mock or session log) | `10.0` to `480.0` minutes |
| $x_3$ | **Failed attempts (5m)** | Count of authentication failures | `0` to `2` failures |
| $x_4$ | **Payload Bytes** | Total KB transmitted during session | `1.0` to `50,000.0` KB |
| $x_5$ | **CPU Utilization** | Host CPU usage percentage | `5.0%` to `50.0%` |
| $x_6$ | **RAM Utilization** | Host memory usage percentage | `20.0%` to `60.0%` |

### Machine Learning Core Classifier
* **Model Type:** **Isolation Forest** (scikit-learn ensemble). Excellent for high-dimensional anomaly detection by isolation paths rather than density clusters.
* **Hyperparameters:** `n_estimators=150`, `contamination=0.01` (1% of base training data assumed to be anomalies).
* **Scaler:** **StandardScaler** mapping features to zero-mean and unit-variance.
* **Inference Output:**
  - Prediction class of `+1` represents inline profile behavior.
  - Prediction class of `-1` represents an outlier.
  - Distance score $< 0.0$ triggers immediate alert generation.
