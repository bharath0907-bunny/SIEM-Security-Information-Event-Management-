# Troubleshooting & Diagnosis Guide

This guide details common system failures, diagnostics commands, and resolutions for operating the SIEM platform.

---

## 1. Elasticsearch / Indexer Node Out of Memory

### Symptom
* Container `wazuh-indexer` crashes, exits continuously, or displays status `unhealthy`.
* Logs from the indexer node report: `java.lang.OutOfMemoryError: Java heap space`.

### Diagnosis
1. Inspect container logs:
   ```bash
   docker logs wazuh-indexer
   ```
2. Verify host memory limits for Elasticsearch map keys count:
   ```bash
   sysctl vm.max_map_count
   ```

### Resolution
* **Increase host virtual memory allocation:** (If it is less than 262144)
  ```bash
  sudo sysctl -w vm.max_map_count=262144
  ```
  Ensure this configuration is persistent in `/etc/sysctl.conf`.
* **Increase JVM Heap Memory allocation:**
  Edit `docker-compose.yml` and increase Java memory parameters for `wazuh-indexer` under `environment`:
  ```yaml
  environment:
    - OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g # Increased from 1g to 2g
  ```

---

## 2. Wazuh Agent Connection Handshake Failures

### Symptom
* Enrolled targets do not appear in the Wazuh dashboard console (status is `never_connected`).
* Target agent logs display: `ERROR: DNS resolution error` or `Connection refused`.

### Diagnosis
1. Inspect agent logs:
   * **Linux:** `tail -n 50 /var/ossec/logs/ossec.log`
   * **Windows:** Check contents of `C:\Program Files (x86)\ossec-agent\ossec.log`
2. Test network connection from target to manager ports:
   ```bash
   nc -zv <MANAGER_IP> 1514
   nc -zv <MANAGER_IP> 1515
   ```

### Resolution
* **Firewall blocks:** Ensure host UFW (or AWS Security Group) is allowing ports `1514` (TCP) and `1515` (TCP) from the target IPs.
* **Incorrect configuration:** Check `/var/ossec/etc/ossec.conf` on the client. Ensure the `<address>` tag contains the correct IP address of the manager server.
* **Restart service:**
  * **Linux:** `systemctl restart wazuh-agent`
  * **Windows:** `Restart-Service -Name "Wazuh"`

---

## 3. SIEM Dashboard "Indexer Unavailable" Error

### Symptom
* Accessing the HTTPS web dashboard page shows: `indexer connection error` or `Kibana server is not ready yet`.

### Diagnosis
* Inspect docker service health states:
  ```bash
  docker compose ps
  ```
* Inspect dashboard connection configurations:
  ```bash
  docker logs wazuh-dashboard
  ```

### Resolution
* Ensure the indexer service is running. If the indexer is unhealthy, the dashboard will fail to load.
* Verify self-signed certificates: The dashboard container logs might show SSL validation errors. Check that `opensearch.ssl.verificationMode: "none"` is configured in `kibana.yml`.

---

## 4. Anomaly Daemon Script Path & Permissions Issues

### Symptom
* Custom `siem-ai-engine` container exits immediately or reports:
  `FileNotFoundError: [Errno 2] No such file or directory: '/var/ossec/logs/alerts/alerts.json'`.

### Diagnosis
* Check docker volume mappings:
  ```bash
  docker inspect wazuh-manager | grep -A 10 "Mounts"
  ```

### Resolution
* Ensure that the volume named `wazuh-manager-logs` is mapped to both `wazuh-manager` (at `/var/ossec/logs`) and `siem-ai-engine` (at `/var/ossec/logs:ro` read-only).
* If running the python script directly on the host (outside Docker), make sure you run it with administrative permissions (`sudo python`) so it can read protected folders:
  ```bash
  sudo chmod 640 /var/ossec/logs/alerts/alerts.json
  ```
