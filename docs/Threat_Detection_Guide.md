# Threat Detection & Rules Engineering Guide

This guide describes the rules engine, log parsers, and custom threat detection rules implemented in the SIEM platform.

---

## 1. Severity Classification Scale

The SIEM Platform leverages Wazuh's 1-15 severity scaling system to grade threat risks:

| Severity Level | Classification | Trigger Profile | SIEM Routing Action |
| :---: | :--- | :--- | :--- |
| **0 - 3** | Information | Standard operations (successful login, daemon startup) | Logged to database index only. |
| **4 - 6** | Low Risk | Minor anomalies, single login failure, package upgrades | Logged to database. Filtered out from alert pipelines. |
| **7 - 9** | Warning / Medium | Repeated failed actions, unauthorized sudo, CPU spikes | Slack/Telegram routing. |
| **10 - 12** | High Risk | Critical brute-forcing, reverse shell commands, cryptomining | High-priority Slack/Telegram alerts, Email warnings, Active Response IP block. |
| **13 - 15** | Critical Threat | System compromises, multi-host attacks, root compromises | High-priority alerting channels, immediate Active Response host isolation. |

---

## 2. MITRE ATT&CK Mapping Matrix

All custom rules map directly to specific techniques in the MITRE ATT&CK framework:

| Threat Vector | Rule ID | Alert Severity | MITRE ATT&CK ID | ATT&CK Tactic |
| :--- | :---: | :---: | :--- | :--- |
| SSH Brute Force | `100002` | Level 10 | **T1110** | Credential Access / Brute Force |
| Sudo Privilege Escalation | `100010` | Level 7 | **T1068** | Privilege Escalation / Exploitation |
| Sudo Access Denied | `100011` | Level 9 | **T1078** | Privilege Escalation / Valid Accounts |
| Port Reconnaissance | `100020` | Level 8 | **T1046** | Discovery / Network Service Scanning |
| Spawning Reverse Shells | `100030` | Level 12 | **T1059** | Execution / Command Interpreter |
| Cryptomining Execution | `100031` | Level 11 | **T1496** | Impact / Resource Hijacking |
| Abnormal CPU/RAM Metrics | `100040` | Level 7 | **T1496** | Impact / Resource Hijacking |

---

## 3. Detection Engineering Logic Deep Dive

### A. SSH Brute Force Detection (Rule ID `100002`)
* **Logic:** Built on top of Wazuh system log rules. If the sshd syslog decoder parses an authentication failure event (`5716`), Rule `100001` fires (Level 5).
* **Correlation:** Rule `100002` is configured with correlation conditions: it triggers only when Rule `100001` fires **6 times** from the **same source IP** within a **120-second window**.
* **Response Link:** Once Rule `100002` is triggered, the manager immediately fires the Active Response command `host-deny.sh` to block the IP via iptables.

### B. Privilege Escalation Detection (Rule ID `100010`)
* **Logic:** Monitored via Linux audit logs and auth logs. If a command matches the regex `COMMAND=/usr/bin/su` or `COMMAND=/bin/bash` from a non-root parent process, it indicates a su spawn.
* **Risk Assessment:** Level 7 warning alerts are dispatched, documenting the user, parent process PID, and timestamp.

### C. Network Reconnaissance Detection (Rule ID `100020`)
* **Logic:** Custom program syslog feeds are processed. The custom decoder `custom-syslog-parser` matches inputs matching `portscan`, `Nmap`, or `SYN Scan` from firewall logs.
* **Correlation:** Parses source IP, triggers a Level 8 warning, and tracks target scan volumes.

### D. Reverse Shell Spawning (Rule ID `100030`)
* **Logic:** Analyzes system process audit events (via `/var/log/audit/audit.log` or standard bash history logs).
* **Regex Match:** Searches for critical command signatures, specifically matching `nc -e`, `nc -c`, `bash -i`, or socket creation strings like `/dev/tcp/`.
* **Action:** Classified as a Critical Level 12 threat. Dispatches alerts across channels and initiates incident containment scripts.
