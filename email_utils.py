import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import EMAIL_CONFIG
import logging
from typing import List, Dict, Any
from datetime import datetime

class EmailSender:
    """Class to handle all email sending operations"""
    
    def __init__(self):
        self.smtp_server = EMAIL_CONFIG['smtp_server']
        self.smtp_port = EMAIL_CONFIG['smtp_port']
        self.sender_email = EMAIL_CONFIG['sender_email']
        self.sender_password = EMAIL_CONFIG['sender_password']
        self.recipient_email = EMAIL_CONFIG['recipient_email']
        self.use_tls = EMAIL_CONFIG['use_tls']

    def _create_message(self, subject: str, body: str) -> MIMEMultipart:
        """Create a MIME message with the given subject and body"""
        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = self.recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        return msg

    def _send_message(self, msg: MIMEMultipart) -> bool:
        """Send the message using SMTP"""
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            return True
        except Exception as e:
            logging.error(f"SMTP Error: {str(e)}")
            return False

    def send_alert(self, subject: str, message: str) -> bool:
        """Send a general alert email"""
        msg = self._create_message(subject, message)
        success = self._send_message(msg)
        if success:
            logging.info(f"Alert email sent successfully: {subject}")
        return success

    def send_change_notification(self, changes: List[Dict[str, Any]]) -> bool:
        """Send a notification about network changes"""
        if not changes:
            return True

        # Group changes by host
        changes_by_host = {}
        for change in changes:
            host_id = change['host_id']
            if host_id not in changes_by_host:
                changes_by_host[host_id] = []
            changes_by_host[host_id].append(change)

        # Prepare email content
        subject = f"Network Changes Detected - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        body = "The following changes were detected in your network:\n\n"

        for host_id, host_changes in changes_by_host.items():
            host_ip = host_changes[0]['host_ip']  # Get IP from first change
            body += f"Host: {host_ip}\n"
            body += "-" * 50 + "\n"

            for change in host_changes:
                body += f"Time: {change['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}\n"
                body += f"Type: {change['change_type']}\n"
                body += f"Details: {change['details']}\n\n"

            body += "\n"

        return self.send_alert(subject, body)

class AlertFormatter:
    """Class to format different types of alerts"""

    @staticmethod
    def format_host_alert(host: Any) -> str:
        """Format host information for email alert"""
        message = f"""
New Host Detected on Network!

Host Details:
-------------
IP Address: {host.ip_address}
MAC Address: {host.mac_address or 'N/A'}
Hostname: {host.hostname or 'N/A'}
Vendor: {host.vendor_info.name if host.vendor_info else 'N/A'}
Operating System: {host.os_details or 'N/A'}
Status: {host.status}
First Seen: {host.last_seen}

Open Ports:
-----------
"""
        
        if host.ports:
            for port in host.ports:
                message += f"""
Port: {port.port_number}/{port.protocol}
State: {port.state}
Service: {port.service_info.name if port.service_info else 'N/A'}
Product: {port.service_info.product if port.service_info else 'N/A'}
Version: {port.service_info.version if port.service_info else 'N/A'}
"""
        else:
            message += "No open ports detected\n"
        
        return message

    @staticmethod
    def format_mac_alert(mac_history: Any) -> str:
        """Format MAC address information for email alert"""
        message = f"""
New Device Detected on Network!

Device Details:
--------------
MAC Address: {mac_history.mac_address}
Vendor: {mac_history.vendor_info.name if mac_history.vendor_info else 'N/A'}
First Seen: {mac_history.first_seen}
Last Seen: {mac_history.last_seen}

Note: This is the first time this device has been seen on the network.
The device might be using a different IP address than before.
"""
        return message

# Create global instances
email_sender = EmailSender()
alert_formatter = AlertFormatter()

# Convenience functions for backward compatibility
def send_alert_email(subject: str, message: str) -> bool:
    """Legacy function to send alert emails"""
    return email_sender.send_alert(subject, message)

def format_host_alert(host: Any) -> str:
    """Legacy function to format host alerts"""
    return alert_formatter.format_host_alert(host)

def format_mac_alert(mac_history: Any) -> str:
    """Legacy function to format MAC alerts"""
    return alert_formatter.format_mac_alert(mac_history)

def send_change_notification(changes: List[Dict[str, Any]]) -> bool:
    """Legacy function to send change notifications"""
    return email_sender.send_change_notification(changes) 