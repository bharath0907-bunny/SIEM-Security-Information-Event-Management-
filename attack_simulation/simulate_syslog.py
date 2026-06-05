#!/usr/bin/env python3
import socket
import time
import sys

def send_syslog(message, host="127.0.0.1", port=514):
    """Sends a raw UDP syslog message to the Wazuh manager."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Standard syslog RFC3164 packet: <PRI>HEADER MSG
        # PRI 30 (daemon.info)
        payload = f"<30>Jun 02 16:30:00 Ubuntu-Production-Target {message}\n"
        sock.sendto(payload.encode("utf-8"), (host, port))
        print(f"Sent: {message}")
    except Exception as e:
        print(f"Error sending message: {e}")
    finally:
        sock.close()

def main():
    print("======================================================================")
    print("                SIEM Syslog Attack Vector Simulator                    ")
    print("======================================================================")
    print("Sending mock syslog alerts to Wazuh UDP port 514...")

    # 1. SSH Brute Force Simulation (15 SSH failed password logs)
    print("\n[*] Simulating SSH Brute Force Attack (15 attempts)...")
    for i in range(15):
        # We use a mock attacker IP: 185.190.140.40
        log_msg = f"sshd[12345]: Failed password for root from 185.190.140.40 port 55321 ssh2"
        send_syslog(log_msg)
        time.sleep(0.4)

    # 2. Network Reconnaissance Port Scan Simulation
    print("\n[*] Simulating Reconnaissance Port Scan...")
    # This matches: program_name = network-sensor, contains "attack detected", "from IP (\S+): (\S+)"
    # Matching rule 100020
    log_msg = "network-sensor: firewall: attack detected from IP 185.190.140.40: portscan"
    send_syslog(log_msg)

    # 3. System Metrics Warning Simulation
    print("\n[*] Simulating System Resource Alert...")
    # Matching rule 100040 and program_name = system-monitor, matches "(\S+) current value: (\S+)"
    log_msg = "system-monitor: CPU_ALERT current value: 96%"
    send_syslog(log_msg)

    print("\n[+] All syslog attack vectors dispatched successfully!")
    print("Check the Wazuh dashboard or Docker logs for siem-ai-engine to verify detection.")

if __name__ == "__main__":
    main()
