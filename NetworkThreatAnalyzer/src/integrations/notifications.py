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

    # Send all notifications
    def send_all_notifications(self, results):
        notifications_sent = []
        errors = []

        # Email notification
        if self._is_email_configured():
            success, message = self.send_email_alert(results)
            if success:
                notifications_sent.append('email')
            else:
                errors.append(f'Email: {message}')

        # Slack notification
        if self.config.get('slack_webhook_url'):
            success, message = self.send_slack_alert(results)
            if success:
                notifications_sent.append('slack')
            else:
                errors.append(f'Slack: {message}')

        # Webhook notification
        if self.config.get('webhook_url'):
            success, message = self.send_webhook_notification(results)
            if success:
                notifications_sent.append('webhook')
            else:
                errors.append(f'Webhook: {message}')

        return notifications_sent, errors

    # Check if the email is configured
    def _is_email_configured(self):
        smtp_config = self.config.get('smtp', {})
        return all([
            smtp_config.get('server'),
            smtp_config.get('username'),
            smtp_config.get('password'),
            self.config.get('notification_emails')
        ])

    # Create email message for threat notification
    def _create_email_message(self, results, recipients, smtp_config):
        summary = self._generate_notification_summary(results)

        message = MIMEMultipart()
        message['From'] = smtp_config['username']
        message['To'] = ', '.join(recipients)
        message['Subject'] = f"Network Threat Alert - {summary['malicious_count']} Malicious IPs Detected"

        # HTML email content
        html_content = self._create_email_html_content(summary, results)
        message.attach(MIMEText(html_content, 'html'))

        return message

    # HTML content for email notification
    def _create_email_html_content(self, summary, results):
        return f"""
    <html>
    <body>
        <h2 style="color: #dc2626;">Network Threat Alert</h2>

        <div style="background: #fef2f2; padding: 20px; border-radius: 8px; margin: 15px 0;">
            <h3>Scan Summary</h3>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total IPs Checked:</strong> {summary['total_ips']}</p>
            <p><strong>Malicious IPs Found:</strong> <span style="color: #dc2626; font-weight: bold;">{summary['malicious_count']}</span></p>
            <p><strong>High Threats:</strong> <span style="color: #dc2626; font-weight: bold;">{summary['high_threats']}</span></p>
            <p><strong>Medium Threats:</strong> <span style="color: #d97706; font-weight: bold;">{summary['medium_threats']}</span></p>
        </div>

        {self._create_threats_table_html(results)}

        <div style="margin-top: 20px; padding: 15px; background: #f0f9ff; border-radius: 6px;">
            <h4>Recommended Actions:</h4>
            <ul>
                <li>Block high threat IPs in firewall immediately</li>
                <li>Investigate network traffic from these IPs</li>
                <li>Review security logs for suspicious activity</li>
                <li>Update security policies if necessary</li>
            </ul>
        </div>

        <hr style="margin: 20px 0;">
        <p style="color: #6b7280; font-size: 0.9em;">
            This alert was generated by Network Threat Analyzer.<br>
            Please review the full report for detailed information.
        </p>
    </body>
    </html>
            """
