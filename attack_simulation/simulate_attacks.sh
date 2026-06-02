#!/usr/bin/env bash
# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - Attack Simulation Shell Menu
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SIMULATOR_PY="$(dirname "$0")/simulate_attacks.py"

print_header() {
    clear
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${CYAN}           SIEM Threat Detection Attack Simulation Lab          ${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${YELLOW}[!] WARNING: Run this simulator in sandbox environments ONLY.${NC}"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"
}

run_sim() {
    local mode=$1
    local target=${2:-"127.0.0.1"}
    echo -e "${GREEN}[*] Launching simulation mode: ${mode} targeting ${target}...${NC}"
    python3 "$SIMULATOR_PY" --mode "$mode" --target "$target"
    echo -e "${CYAN}Press Enter to return to menu...${NC}"
    read -r
}

# Main Loop
while true; do
    print_header
    echo -e "1) ${GREEN}Simulate SSH Brute Force${NC}"
    echo -e "2) ${GREEN}Simulate Reconnaissance Port Scan (Nmap-like)${NC}"
    echo -e "3) ${GREEN}Simulate Privilege Escalation (Sudo/Su misuse)${NC}"
    echo -e "4) ${GREEN}Simulate Reverse Shell Execution Fingerprint${NC}"
    echo -e "5) ${GREEN}Run All Simulation Vectors${NC}"
    echo -e "6) ${RED}Exit Lab${NC}"
    echo -e "${CYAN}----------------------------------------------------------------${NC}"
    echo -n "Select option [1-6]: "
    read -r opt

    case $opt in
        1)
            echo -n "Enter target IP (default: 127.0.0.1): "
            read -r ip
            run_sim "ssh" "${ip:-127.0.0.1}"
            ;;
        2)
            echo -n "Enter target IP (default: 127.0.0.1): "
            read -r ip
            run_sim "scan" "${ip:-127.0.0.1}"
            ;;
        3)
            run_sim "privesc" "127.0.0.1"
            ;;
        4)
            run_sim "shell" "127.0.0.1"
            ;;
        5)
            echo -n "Enter target IP (default: 127.0.0.1): "
            read -r ip
            run_sim "all" "${ip:-127.0.0.1}"
            ;;
        6)
            echo -e "${GREEN}[*] Exiting lab. Safe coding!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Invalid choice, try again.${NC}"
            sleep 1
            ;;
    esac
done
