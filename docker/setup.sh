#!/bin/bash
# =============================================================================
# SIEM Stack First-Time Setup Script
# Run this ONCE after cloning the repo on a fresh system.
# Usage: cd docker && bash setup.sh
# =============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || error "Docker not found. Install Docker first."
docker compose version >/dev/null 2>&1 || error "Docker Compose v2 not found."

# ── Step 1: Bring up all services ─────────────────────────────────────────────
info "Starting all containers..."
docker compose up -d

# ── Step 2: Wait for indexer to be healthy ────────────────────────────────────
info "Waiting for Wazuh Indexer to become healthy (may take 60s)..."
for i in $(seq 1 30); do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' wazuh-indexer 2>/dev/null || echo "starting")
  if [ "$STATUS" = "healthy" ]; then
    info "Indexer is healthy."
    break
  fi
  [ "$i" -eq 30 ] && error "Indexer did not become healthy in time."
  sleep 5
done

# ── Step 3: Initialize OpenSearch security index ──────────────────────────────
info "Initializing OpenSearch security (securityadmin.sh)..."
docker exec -u root wazuh-indexer bash -c "
  chmod +x /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh
  export JAVA_HOME=/usr/share/wazuh-indexer/jdk
  /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd /usr/share/wazuh-indexer/opensearch-security \
    -icl -nhnv \
    -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
    -cert  /usr/share/wazuh-indexer/certs/admin.pem \
    -key   /usr/share/wazuh-indexer/certs/admin-key.pem \
    -h localhost -p 9200
" || warn "securityadmin may have already run (index exists). Continuing..."

# ── Step 4: Wait for manager to start ─────────────────────────────────────────
info "Waiting for Wazuh Manager (60s)..."
sleep 60

# ── Step 5: Fix Wazuh API passwords ───────────────────────────────────────────
info "Setting Wazuh API passwords..."
docker exec wazuh-manager /var/ossec/framework/python/bin/python3 - << 'PYEOF'
import sys, sqlite3
sys.path.insert(0, '/var/ossec/framework/python/lib/python3.9/site-packages')
from werkzeug.security import generate_password_hash
pwd = 'SecretPassword123!'
hashed = generate_password_hash(pwd)
conn = sqlite3.connect('/var/ossec/api/configuration/security/rbac.db')
cur = conn.cursor()
cur.execute('UPDATE users SET password=? WHERE username=?', (hashed, 'wazuh'))
cur.execute('UPDATE users SET password=? WHERE username=?', (hashed, 'wazuh-wui'))
conn.commit()
conn.close()
print('API passwords updated OK')
PYEOF

# ── Step 6: Restart manager so new passwords take effect ─────────────────────
info "Restarting Wazuh Manager to apply API password changes..."
docker exec wazuh-manager /var/ossec/bin/wazuh-control restart || true
sleep 15

# ── Step 7: Verify ────────────────────────────────────────────────────────────
info "Verifying API authentication..."
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
  -u wazuh-wui:SecretPassword123! \
  -X POST https://localhost:55000/security/user/authenticate)

if [ "$HTTP_CODE" = "200" ]; then
  info "✅ Wazuh API authenticated successfully."
else
  warn "API returned HTTP $HTTP_CODE — may need another minute to start."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  SIEM Stack is ready!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  Wazuh Dashboard : http://localhost:5601"
echo "    Username       : admin"
echo "    Password       : admin"
echo ""
echo "  Custom SIEM UI  : http://localhost:8080"
echo "  Wazuh API       : https://localhost:55000"
echo "    Username       : wazuh-wui"
echo "    Password       : SecretPassword123!"
echo ""
echo -e "${YELLOW}Note: To stop all services:  docker compose down${NC}"
echo -e "${YELLOW}      To wipe all data:       docker compose down -v${NC}"
echo -e "${YELLOW}      After a fresh 'down -v' you must run setup.sh again.${NC}"
