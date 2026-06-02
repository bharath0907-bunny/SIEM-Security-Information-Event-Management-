# Installation & Deployment Guide

This guide details the step-by-step installation process of the Enterprise SIEM & Threat Detection Platform in a laboratory environment.

---

## System Requirements

| Parameter | Recommended Specification (SIEM Host) | Minimum Specification (SIEM Host) |
| :--- | :--- | :--- |
| **Operating System** | Ubuntu Server 22.04 LTS | Ubuntu Server 20.04 LTS / Debian 11 |
| **CPU Cores** | 4 vCPUs | 2 vCPUs |
| **System Memory** | 8 GB RAM | 4 GB RAM (strictly enforced) |
| **Disk Capacity** | 50 GB SSD | 30 GB HDD |

> [!WARNING]
> Running the Elasticsearch cluster indexer requires setting memory map parameters. If this is not done, the container will exit immediately on launch. The `setup_env.sh` script automates this config.

---

## Step 1: Host Environment Setup

Clone this repository to your SIEM server, navigate to the setup directory, and run the host configuration script:

```bash
chmod +x deployment/setup_env.sh
sudo ./deployment/setup_env.sh
```

This script:
1. Installs Docker & Docker Compose if they are not present.
2. Updates `sysctl` settings, adding `vm.max_map_count=262144`.
3. Configures UFW firewall rules, opening ports `1514` (agent communications), `1515` (agent registrations), `443` (Dashboard web console), and `514` (Logstash Syslog).

---

## Step 2: Deploy the Docker SIEM Stack

Navigate to the `docker` subdirectory and launch the stack:

```bash
cd docker
docker compose up -d
```

### Verify Container Health
Allow up to 60-90 seconds for Elasticsearch and Wazuh Manager services to boot and execute internal certificates configurations. Run the check command:

```bash
docker compose ps
```

Ensure all containers (`wazuh-indexer`, `wazuh-manager`, `wazuh-filebeat`, `wazuh-dashboard`, `logstash`, and `siem-ai-engine`) display status as **Up (healthy)**.

---

## Step 3: Access the SOC Web Console

Open your web browser and navigate to:
```text
https://<YOUR_SIEM_SERVER_IP>:443
```

* **Bypass SSL Warnings:** The container employs self-signed TLS certificates for development. Click "Advanced" and select "Proceed to..." to open the login portal.
* **Credentials:**
  - **Username:** `admin`
  - **Password:** `admin` (or the customized password defined inside `.env` configurations).

---

## Step 4: Enrolling Monitored Client Agents

To ingest log telemetry, agents must be deployed on the target hosts.

### A. Deploying Linux Target Agents
1. Copy the script [agent_linux_install.sh](file:///c:/Users/appal/OneDrive/Attachments/Desktop/adobe/scripts/monitoring/agent_linux_install.sh) onto the target Linux machine.
2. Run the script as root, passing the SIEM Server's IP address as an argument:
   ```bash
   chmod +x agent_linux_install.sh
   sudo ./agent_linux_install.sh <YOUR_SIEM_SERVER_IP>
   ```
3. The script automatically adds the Wazuh repo, installs the client package, sets the manager configuration in `/var/ossec/etc/ossec.conf`, and enables/starts the service.

### B. Deploying Windows Target Agents
1. Copy the PowerShell script [agent_windows_config.ps1](file:///c:/Users/appal/OneDrive/Attachments/Desktop/adobe/scripts/monitoring/agent_windows_config.ps1) onto the target Windows machine.
2. Open PowerShell with **Administrative Privileges** (Right-click -> Run as Administrator).
3. Execute the script, pointing it to your Wazuh Manager IP:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\agent_windows_config.ps1 -ManagerIP "<YOUR_SIEM_SERVER_IP>"
   ```
4. This script downloads the MSI package, executes a quiet install registering the client, and updates client registries to parse PowerShell operational events and Sysmon telemetry.

---

## Step 5: Verify Connectivity

To confirm agents are transmitting security events to the SIEM:
1. Log in to the Wazuh Web console.
2. Navigate to **Wazuh** -> **Agents**.
3. Confirm both the Linux and Windows target hosts appear in the active agents list with a green **Active** connection status icon.
