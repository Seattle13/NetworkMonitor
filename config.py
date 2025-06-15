import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_env_int(key, default):
    """Safely get an integer from environment variables with a default value"""
    value = os.getenv(key)
    try:
        return int(value) if value is not None else default
    except (ValueError, TypeError):
        return default

# Email Configuration
EMAIL_CONFIG = {
    'smtp_server': os.getenv('SMTP_SERVER'),
    'smtp_port': get_env_int('SMTP_PORT', 587),
    'sender_email': os.getenv('SENDER_EMAIL'),
    'sender_password': os.getenv('SENDER_PASSWORD'),
    'recipient_email': os.getenv('RECIPIENT_EMAIL'),
    'use_tls': os.getenv('USE_TLS') == 'true'
}

# Application Configuration
APP_CONFIG = {
    'scan_interval': get_env_int('SCAN_INTERVAL', 5),  # Default to 5 minutes
    'dashboard_refresh': get_env_int('DASHBOARD_REFRESH', 30),  # Default to 30 seconds
    'network_cidr': os.getenv('NETWORK_CIDR', '192.168.0.0/24')  # Default network
}

# Database Configuration
DB_CONFIG = {
    'uri': os.getenv('DATABASE_URI', 'sqlite:///network_scan.db')  # Default database
}

# Web Server Configuration
SERVER_CONFIG = {
    'host': os.getenv('FLASK_HOST', '127.0.0.1'),
    'port': get_env_int('FLASK_PORT', 8080),
    'debug': os.getenv('FLASK_DEBUG', 'false').lower() == 'true',
    'threads': get_env_int('WAITRESS_THREADS', 4)
}

# Logging Configuration
LOG_CONFIG = {
    'file': os.getenv('LOG_FILE', 'network_scanner.log'),
    'level': os.getenv('LOG_LEVEL', 'INFO')
} 