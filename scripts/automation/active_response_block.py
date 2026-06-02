#!/usr/bin/env python3
# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - Active Response Dynamic Blocker
# ==============================================================================
# Description: Cross-platform script executed by Wazuh agent to block attacking
#              source IPs using iptables (Linux) or netsh (Windows).
# ==============================================================================

import os
import sys
import json
import subprocess
import platform

ACTIVE_RESPONSE_LOG = os.environ.get("AR_LOG_PATH", "/var/ossec/logs/active-responses.log")

def write_log(message):
    """Appends messages to the central active response tracking file."""
    timestamp = subprocess.check_output(['date', '+%Y-%m-%d %H:%M:%S']).decode().strip() if platform.system() != 'Windows' else "WINDOWSHOST"
    log_line = f"{timestamp} SIEM-AR: {message}\n"
    try:
        # Create directories if not existing
        log_dir = os.path.dirname(ACTIVE_RESPONSE_LOG)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        with open(ACTIVE_RESPONSE_LOG, 'a') as f:
            f.write(log_line)
    except IOError:
        pass
    print(message)

def block_ip(ip):
    """Executes OS-specific block commands."""
    os_type = platform.system().lower()
    
    if 'linux' in os_type:
        # Block using iptables
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            write_log(f"Blocked IP {ip} successfully using iptables DROP rules.")
            return True
        except subprocess.CalledProcessError as e:
            write_log(f"Failed to block IP {ip} via iptables. Error: {e.stderr.decode().strip()}")
            
    elif 'windows' in os_type:
        # Block using netsh advanced firewall
        cmd = f'netsh advfirewall firewall add rule name="SIEM Block {ip}" dir=in action=block remoteip={ip}'
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            write_log(f"Blocked IP {ip} successfully using Windows Netsh Firewall rule.")
            return True
        except subprocess.CalledProcessError as e:
            write_log(f"Failed to block IP {ip} on Windows. Error: {e.stderr.decode().strip()}")
            
    else:
        write_log(f"Unsupported OS platform type: {os_type} for IP blocking.")
    return False

def unblock_ip(ip):
    """Executes OS-specific unblock commands (timeout cleanup)."""
    os_type = platform.system().lower()
    
    if 'linux' in os_type:
        # Unblock using iptables delete
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            write_log(f"Unblocked IP {ip} successfully using iptables deletion.")
            return True
        except subprocess.CalledProcessError as e:
            write_log(f"Failed to unblock IP {ip} via iptables. Error: {e.stderr.decode().strip()}")
            
    elif 'windows' in os_type:
        # Remove netsh firewall blocking rule
        cmd = f'netsh advfirewall firewall delete rule name="SIEM Block {ip}"'
        try:
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            write_log(f"Unblocked IP {ip} successfully by deleting Windows Netsh Firewall rule.")
            return True
        except subprocess.CalledProcessError as e:
            write_log(f"Failed to unblock IP {ip} on Windows. Error: {e.stderr.decode().strip()}")
            
    else:
        write_log(f"Unsupported OS platform type: {os_type} for IP unblocking.")
    return False

def main():
    # Read Wazuh active response input parameters from stdin (JSON format)
    input_str = ""
    for line in sys.stdin:
        input_str += line
        
    if not input_str.strip():
        write_log("No inputs received via stdin. Active Response aborted.")
        sys.exit(1)
        
    try:
        data = json.loads(input_str)
        action = data.get("command")
        parameters = data.get("parameters", {})
        alert = parameters.get("alert", {})
        
        # Pull source IP address
        src_ip = alert.get("data", {}).get("srcip", alert.get("srcip"))
        
        if not src_ip:
            # Fallback to check nested arguments
            src_ip = parameters.get("srcip")
            
        if not src_ip or src_ip == "0.0.0.0":
            write_log("Could not resolve valid source IP address from incident parameters. Exiting.")
            sys.exit(1)
            
        if action == "add":
            write_log(f"Initiating isolation block command for malicious target: {src_ip}")
            block_ip(src_ip)
        elif action == "delete":
            write_log(f"Timeout expiration reached. Unblocking target: {src_ip}")
            unblock_ip(src_ip)
        else:
            write_log(f"Invalid Active Response action received: {action}")
            
    except Exception as e:
        write_log(f"Critical execution crash inside Active Response script: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
