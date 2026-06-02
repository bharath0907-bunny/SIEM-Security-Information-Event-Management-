#!/usr/bin/env python3
# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - AWS GuardDuty Event Bridge
# ==============================================================================
# Description: Parses AWS GuardDuty JSON findings, maps finding severities and
#              contexts, and forwards logs to the SIEM Logstash parser via UDP/TCP.
# ==============================================================================

import os
import json
import socket
import logging

# Configure logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# SIEM endpoint variables (Environment variable targets or fallback defaults)
SIEM_LOGSTASH_HOST = os.environ.get("SIEM_LOGSTASH_HOST", "127.0.0.1")
SIEM_LOGSTASH_PORT = int(os.environ.get("SIEM_LOGSTASH_PORT", "514"))
PROTOCOL = os.environ.get("SIEM_FORWARDING_PROTOCOL", "UDP").upper()

def send_to_siem(payload):
    """Sends the serialized payload string to the SIEM ingestion pipeline."""
    payload_bytes = (payload + "\n").encode("utf-8")
    
    try:
        if PROTOCOL == "TCP":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect((SIEM_LOGSTASH_HOST, SIEM_LOGSTASH_PORT))
                s.sendall(payload_bytes)
        else: # Default UDP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5.0)
                s.sendto(payload_bytes, (SIEM_LOGSTASH_HOST, SIEM_LOGSTASH_PORT))
        logger.info(f"Successfully forwarded GuardDuty finding to SIEM: {SIEM_LOGSTASH_HOST}:{SIEM_LOGSTASH_PORT}")
        return True
    except Exception as e:
        logger.error(f"Failed to forward message to SIEM server: {e}")
        return False

def parse_guardduty_finding(finding):
    """Normalizes GuardDuty JSON finding structure into standard syslog event details."""
    finding_id = finding.get("id", "unknown-id")
    detail_type = finding.get("type", "unknown-type")
    severity = finding.get("severity", 0.0)
    region = finding.get("region", "unknown-region")
    title = finding.get("title", "No Title")
    description = finding.get("description", "")
    
    # Map raw numeric severity to standard strings
    if severity >= 7.0:
        severity_label = "CRITICAL"
    elif severity >= 4.0:
        severity_label = "WARNING"
    else:
        severity_label = "INFO"
        
    # Extract affected resource info
    resource = finding.get("resource", {})
    resource_type = resource.get("resourceType", "unknown-resource")
    instance_id = resource.get("instanceDetails", {}).get("instanceId", "N/A")
    
    # Extract network connection actor details
    action = finding.get("service", {}).get("action", {})
    actor_ip = "N/A"
    
    # Extract remote connection actor IP if available
    network_connection = action.get("networkConnectionAction", {})
    if network_connection:
        actor_ip = network_connection.get("remoteIpDetails", {}).get("ipAddressV4", "N/A")
        
    # Format standard Logstash/syslog string payload
    normalized_alert = {
        "sensor_type": "aws-guardduty",
        "finding_id": finding_id,
        "finding_type": detail_type,
        "severity": severity_label,
        "severity_score": severity,
        "region": region,
        "title": title,
        "description": description,
        "affected_resource_type": resource_type,
        "affected_instance_id": instance_id,
        "attacker_source_ip": actor_ip,
        "message": f"AWS GuardDuty Alert [{severity_label}] - Title: {title} | Target Instance: {instance_id} | Attacker IP: {actor_ip}"
    }
    
    return json.dumps(normalized_alert)

def lambda_handler(event, context):
    """
    AWS Lambda Entrypoint handler.
    Triggered by Amazon EventBridge (CloudWatch Events) matching GuardDuty findings.
    """
    logger.info("Ingesting raw AWS GuardDuty event trigger...")
    
    # Extract detail from EventBridge schema
    finding_detail = event.get("detail", event)
    
    if not finding_detail:
        logger.warning("Empty finding content received in payload. Skipping.")
        return {
            'statusCode': 400,
            'body': json.dumps('Empty payload message')
        }
        
    normalized_syslog = parse_guardduty_finding(finding_detail)
    status = send_to_siem(normalized_syslog)
    
    return {
        'statusCode': 200 if status else 500,
        'body': json.dumps('Event forwarding complete.')
    }

# Standalone manual local validation execution
if __name__ == '__main__':
    print("[*] GuardDuty Event forwarder offline validation test...")
    # Mock finding payload
    mock_event = {
        "id": "gd-mock-finding-id-12345",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "severity": 8.0,
        "region": "us-east-1",
        "title": "SSH brute force attack against EC2 instance i-0abcdef123456",
        "description": "An EC2 instance is experiencing SSH brute force attempts from a known malicious IP.",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-0abcdef123456"
            }
        },
        "service": {
            "action": {
                "networkConnectionAction": {
                    "remoteIpDetails": {
                        "ipAddressV4": "198.51.100.42"
                    }
                }
            }
        }
    }
    
    print("[*] Parsing mock GuardDuty finding...")
    parsed_json = parse_guardduty_finding(mock_event)
    print(f"[+] Normalized Ingestion Payload:\n{json.dumps(json.loads(parsed_json), indent=2)}")
    print("[*] Attempting local forwarding simulation...")
    send_to_siem(parsed_json)
