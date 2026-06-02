#!/bin/bash
# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - Linux Agent Installer
# ==============================================================================
# Description: Automates Wazuh agent installation, sets manager configuration,
#              and registers log monitoring for core Linux log channels.
# Usage: sudo ./agent_linux_install.sh <WAZUH_MANAGER_IP>
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[*] $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}"
}

error() {
    echo -e "${RED}[ERR] $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}" >&2
}

if [ "$#" -ne 1 ]; then
    error "Usage: sudo $0 <WAZUH_MANAGER_IP>"
    exit 1
fi

MANAGER_IP="$1"

if [ "$EUID" -ne 0 ]; then
    error "Please run this script as root (sudo)."
    exit 1
fi

log "Initializing Wazuh Agent installation on monitored Linux target..."

# 1. Add Wazuh Repository GPG key and repo
log "Adding Wazuh APT repositories..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/etc/apt/trusted.gpg.d/wazuh.gpg --import
chmod 644 /etc/apt/trusted.gpg.d/wazuh.gpg

echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
apt-get update -y

# 2. Install Wazuh Agent
log "Installing wazuh-agent package..."
WAZUH_MANAGER="$MANAGER_IP" apt-get install -y wazuh-agent

# 3. Configure log files to monitor in agent ossec.conf
log "Configuring client ossec.conf for log ingestion..."
AGENT_CONF="/var/ossec/etc/ossec.conf"

# Backup default config
cp "$AGENT_CONF" "${AGENT_CONF}.bak"

# Inject standard system monitoring targets into agent config
cat <<EOF > "$AGENT_CONF"
<ossec_config>
  <client>
    <server>
      <address>$MANAGER_IP</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu20, ubuntu20.04</config-profile>
  </client>

  <!-- Local Log Collection -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <!-- Monitor Sudo Commands and Access Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <!-- Webserver Log collection (conditional check) -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>

  <!-- System commands auditing -->
  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 5</command>
    <frequency>360</frequency>
  </localfile>

</ossec_config>
EOF

log "Agent config successfully updated to point to SIEM manager: $MANAGER_IP"

# 4. Enable and start Agent service
log "Starting Wazuh Agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

log "Wazuh Agent installed, configured, and running."
log "Please check the SIEM dashboard console to verify agent connection status."
