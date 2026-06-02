#!/bin/bash
# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - Host Environment Setup
# ==============================================================================
# Description: Installs Docker, Docker Compose, configures network/sysctl rules
#              and updates UFW firewall rules for secure internal traffic.
# Usage: sudo ./setup_env.sh
# ==============================================================================

set -euo pipefail

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[*] $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}"
}

warn() {
    echo -e "${YELLOW}[!] $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}"
}

error() {
    echo -e "${RED}[ERR] $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}" >&2
}

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
    error "Please run this script as root (sudo)."
    exit 1
fi

log "Starting host environment setup for SIEM platform..."

# 1. Update OS package repositories
log "Updating package list..."
apt-get update -y

# 2. Configure kernel settings for Elasticsearch/Wazuh Indexer
log "Configuring system limits for Elasticsearch..."
SYSCTL_CONF="/etc/sysctl.d/99-siem.conf"
if [ ! -f "$SYSCTL_CONF" ] || ! grep -q "vm.max_map_count" "$SYSCTL_CONF"; then
    echo "vm.max_map_count=262144" >> "$SYSCTL_CONF"
    sysctl -p "$SYSCTL_CONF"
    log "vm.max_map_count set to 262144 successfully."
else
    log "vm.max_map_count is already configured."
fi

# Apply immediately
sysctl -w vm.max_map_count=262144

# Configure system limits for file handles
LIMITS_CONF="/etc/security/limits.d/99-siem.conf"
if [ ! -f "$LIMITS_CONF" ]; then
    cat <<EOF > "$LIMITS_CONF"
wazuh hard nofile 65536
wazuh soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft nofile 65536
EOF
    log "File descriptor security limits applied."
fi

# 3. Check and Install Docker / Docker Compose
if ! command -v docker &> /dev/null; then
    log "Docker not found. Installing Docker engine..."
    apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io
    log "Docker engine installed."
else
    log "Docker is already installed: $(docker --version)"
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    log "Installing Docker Compose plugin..."
    apt-get install -y docker-compose-plugin
    log "Docker Compose plugin installed."
else
    log "Docker Compose is already installed."
fi

# 4. Configure Local Firewall Rules (UFW)
if command -v ufw &> /dev/null; then
    log "Configuring firewall rules (UFW)..."
    # Basic rules
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow local SSH
    ufw allow 22/tcp comment 'SSH Port'
    
    # Allow Wazuh communication ports
    ufw allow 1514/tcp comment 'Wazuh Agent communication'
    ufw allow 1515/tcp comment 'Wazuh Agent registration'
    ufw allow 514/udp comment 'Syslog ingestion'
    ufw allow 514/tcp comment 'Syslog ingestion TCP'
    
    # Allow Web interface access (Kibana Dashboard)
    ufw allow 443/tcp comment 'Kibana Console (HTTPS)'
    ufw allow 5601/tcp comment 'Kibana UI (Direct)'
    
    # Allow custom API
    ufw allow 55000/tcp comment 'Wazuh REST API'

    # Enable UFW (non-interactively)
    ufw --force enable
    log "UFW Firewall configured and enabled."
else
    warn "UFW is not installed. Skipping firewall rules."
fi

# 5. Create Directory Volumes for persistence
log "Creating data directories for SIEM volume mapping..."
mkdir -p ../docker-volumes/wazuh-indexer-data
mkdir -p ../docker-volumes/wazuh-manager-logs
mkdir -p ../docker-volumes/wazuh-manager-rules
mkdir -p ../docker-volumes/wazuh-manager-decoders
mkdir -p ../docker-volumes/elasticsearch-data
mkdir -p ../docker-volumes/logstash-config
chmod -R 775 ../docker-volumes

log "Environment setup completed successfully!"
log "Next step: Deploy the stack via docker-compose."
