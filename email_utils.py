import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import EMAIL_CONFIG
import logging

def send_alert_email(subject, message):
    """
    Send an email alert using the configured SMTP settings.
    
    Args:
        subject (str): Email subject
        message (str): Email message body
    """
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['sender_email']
        msg['To'] = EMAIL_CONFIG['recipient_email']
        msg['Subject'] = subject

        # Add message body
        msg.attach(MIMEText(message, 'plain'))

        # Create SMTP session
        with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
            if EMAIL_CONFIG['use_tls']:
                server.starttls()
            
            # Login to SMTP server
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            
            # Send email
            server.send_message(msg)
            
        logging.info(f"Alert email sent successfully: {subject}")
        return True
    except Exception as e:
        logging.error(f"Failed to send alert email: {str(e)}")
        return False

def format_host_alert(host):
    """
    Format host information for email alert.
    
    Args:
        host (Host): Host object from database
    Returns:
        str: Formatted message
    """
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

def format_mac_alert(mac_history):
    """
    Format MAC address information for email alert.
    
    Args:
        mac_history (MACHistory): MACHistory object from database
    Returns:
        str: Formatted message
    """
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