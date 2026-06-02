#!/usr/bin/env python3
# ==============================================================================
# Enterprise SIEM & Threat Detection Platform - Centralized Alert Manager
# ==============================================================================
# Description: Interfaces with Slack Webhooks, Telegram Bot APIs, and SMTP servers
#              to dispatch rich formatted security notifications.
# ==============================================================================

import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

# Load config from environment variables (defaults for local execution)
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
SMTP_SERVER = os.environ.get("SMTP_SERVER", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
ALERT_RECIPIENT = os.environ.get("ALERT_RECIPIENT", "security-team@siem-platform.local")

class AlertManager:
    def __init__(self):
        print("[*] Alert Manager initialized.")
        if not SLACK_WEBHOOK_URL:
            print("[-] Slack Webhook URL not set. Slack alerts disabled.")
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            print("[-] Telegram Credentials not set. Telegram alerts disabled.")
        if not SMTP_USER or not SMTP_PASSWORD:
            print("[-] SMTP Creds not set. Email alerts disabled.")

    def send_slack(self, text, blocks=None):
        """Dispatches structured messages to Slack Webhook."""
        if not SLACK_WEBHOOK_URL or "YOUR_SLACK" in SLACK_WEBHOOK_URL:
            return False
            
        payload = {"text": text}
        if blocks:
            payload["blocks"] = blocks
            
        try:
            response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
            if response.status_code == 200:
                return True
            print(f"[ERR] Slack webhook returned error code: {response.status_code}")
        except Exception as e:
            print(f"[ERR] Slack connection failure: {e}")
        return False

    def send_telegram(self, message):
        """Sends rich markdown messages to Telegram Group/Chat."""
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or "YOUR_TELEGRAM" in TELEGRAM_BOT_TOKEN:
            return False
            
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        try:
            response = requests.post(url, json=payload, timeout=5)
            if response.status_code == 200:
                return True
            print(f"[ERR] Telegram API error: {response.text}")
        except Exception as e:
            print(f"[ERR] Telegram connection failure: {e}")
        return False

    def send_email(self, subject, body_html):
        """Sends HTML security notifications via SMTP."""
        if not SMTP_USER or not SMTP_PASSWORD or "your_email" in SMTP_USER:
            return False
            
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = SMTP_USER
        msg['To'] = ALERT_RECIPIENT
        
        msg.attach(MIMEText(body_html, 'html'))
        
        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ALERT_RECIPIENT, msg.as_string())
            server.quit()
            return True
        except Exception as e:
            print(f"[ERR] SMTP mail dispatch failure: {e}")
        return False

    def dispatch_anomaly_alert(self, anomaly):
        """Formats and distributes AI anomaly notifications across channels."""
        score = anomaly["score"]
        ip = anomaly["source_ip"]
        agent = anomaly["agent"]
        base_desc = anomaly["base_rule_description"]
        features = anomaly["extracted_features"]
        
        # Severity ranking based on outlier score
        severity = "⚠️ HIGH ANOMALY" if score < -0.15 else "🚨 CRITICAL ANOMALY"
        emoji = "🚨" if score < -0.15 else "🔥"
        
        # 1. Format Slack Blocks
        slack_blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} AI SIEM Anomaly Detected {emoji}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* `{severity}`"},
                    {"type": "mrkdwn", "text": f"*Anomaly Score:* `{score:.4f}`"},
                    {"type": "mrkdwn", "text": f"*Source IP:* `{ip}`"},
                    {"type": "mrkdwn", "text": f"*Target Node:* `{agent}`"},
                    {"type": "mrkdwn", "text": f"*Base Event:* {base_desc}"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*ML Extracted Profiles:*\n"
                            f"• Login Hour: `{features['login_hour']:.1f}:00`\n"
                            f"• Failed attempts (5m window): `{features['failed_attempts_5m']}`\n"
                            f"• CPU load: `{features['cpu_utilization']:.1f}%`\n"
                            f"• Network Vol: `{features['data_transmitted_kb']:.2f} KB`"
                }
            }
        ]
        self.send_slack(f"AI Anomaly Detected from IP: {ip}", blocks=slack_blocks)
        
        # 2. Format Telegram Markdown
        telegram_msg = (
            f"*{emoji} AI SIEM ANOMALY DETECTED {emoji}*\n\n"
            f"*Severity:* `{severity}`\n"
            f"*Outlier Score:* `{score:.4f}`\n"
            f"*Offending IP:* `{ip}`\n"
            f"*Target Agent:* `{agent}`\n"
            f"*Description:* `{base_desc}`\n\n"
            f"*ML Feature Profile:*\n"
            f"• Hour: `{features['login_hour']:.1f}`\n"
            f"• Fails (5m): `{features['failed_attempts_5m']}`\n"
            f"• CPU: `{features['cpu_utilization']:.1f}%`\n"
            f"• Data: `{features['data_transmitted_kb']:.1f} KB`"
        )
        self.send_telegram(telegram_msg)
        
        # 3. Format Email HTML
        subject = f"[SIEM ALERT] - AI Anomaly Detected on Node: {agent}"
        email_html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="background-color: #7b1fa2; color: #fff; padding: 15px; font-size: 20px; font-weight: bold; border-radius: 5px 5px 0 0;">
                    {emoji} AI Anomaly Alarm Triggered
                </div>
                <div style="border: 1px solid #7b1fa2; padding: 20px; border-radius: 0 0 5px 5px;">
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr style="background-color: #f3e5f5;"><td style="padding: 10px; font-weight: bold;">Severity</td><td style="padding: 10px; color: red;">{severity}</td></tr>
                        <tr><td style="padding: 10px; font-weight: bold;">Isolation Forest Score</td><td style="padding: 10px;">{score:.4f}</td></tr>
                        <tr style="background-color: #f3e5f5;"><td style="padding: 10px; font-weight: bold;">Source IP Address</td><td style="padding: 10px;"><b>{ip}</b></td></tr>
                        <tr><td style="padding: 10px; font-weight: bold;">Target Host Name</td><td style="padding: 10px;">{agent}</td></tr>
                        <tr style="background-color: #f3e5f5;"><td style="padding: 10px; font-weight: bold;">Related Action Log</td><td style="padding: 10px;">{base_desc}</td></tr>
                    </table>
                    <h3>ML Profile Feature Map</h3>
                    <ul>
                        <li>Login Time Parameter (Hour): {features['login_hour']:.1f}</li>
                        <li>Failed Authentications (5 Minutes): {features['failed_attempts_5m']}</li>
                        <li>Telemetry Metric - CPU Utilization: {features['cpu_utilization']:.1f}%</li>
                        <li>Telemetry Metric - Memory Usage: {features['ram_utilization']:.1f}%</li>
                        <li>Data Payload Vol Transmitted: {features['data_transmitted_kb']:.2f} KB</li>
                    </ul>
                    <p style="font-size: 12px; color: #777; margin-top: 20px; border-top: 1px solid #ddd; padding-top: 10px;">
                        This notification was dynamically generated by the Enterprise SIEM Anomaly Detection Platform machine learning agent.
                    </p>
                </div>
            </body>
        </html>
        """
        self.send_email(subject, email_html)
