"""
Notification integration
"""
import smtplib
from http.client import responses
from pyexpat.errors import messages

import requests
import json

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from src.config.settings import load_config


# Notification manager
class NotificationManager:
    def __init__(self):
        self.config = load_config()

    # Send email notification for threat detection
    def send_email_alert(self, results, recipients=None):
        if not self._is_email_configured():
            return False, "Email not configured"

        try:
            smtp_config = self.config.get('smtp', {})
            recipients = recipients or self.config.get('notification_emails', [])

            if not recipients:
                return False, "No recipients configured"

            message = self._create_email_message(results, recipients, smtp_config)

            with smtplib.SMTP(smtp_config['server'], smtp_config.get('port', 587)) as server:
                if smtp_config.get('tls', True):
                    server.starttls()
                if smtp_config.get('username'):
                    server.login(smtp_config['username'], smtp_config['password'])
                server.send_message(message)

            return True, "Email sent successfully"
        except Exception as e:
            return False, f"Email sending failed: {str(e)}"

    # Send Slack notification
    def send_slack_alert(self, results, webhook_url=None):
        webhook_url = webhook_url or self.config.get('slack_webhook_url')

        if not webhook_url:
            return False, "Slack webhook URL not configured"

        try:
            summary = self._generate_notification_summary(results)
            payload = self._create_slack_payload(summary)

            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                return True, "Slack notification sent"
            else:
                return False, f"Slack API error: {response.status_code}"

        except Exception as e:
            return False, f"Slack notification failed: {str(e)}"

    # send webhook notification
    def send_webhook_notification(self, results, webhook_url=None):

        webhook_url = webhook_url or self.config.get('webhook_url')

        if not webhook_url:
            return False, "Webhook URL not configured"

        try:
            payload = {
                'timestamp': datetime.now().isoformat(),
                'source': 'Network Threat Analyzer',
                'results': results
            }

            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code in [200, 201, 202]:
                return True, "Webhook notification sent"
            else:
                return False, f"Webhook error: {response.status_code}"

        except Exception as e:
            return False, f"Webhook notification failed: {str(e)}"
