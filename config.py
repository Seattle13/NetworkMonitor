import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Email Configuration
EMAIL_CONFIG = {
    'smtp_server': os.getenv('SMTP_SERVER'),
    'smtp_port': int(os.getenv('SMTP_PORT')),
    'sender_email': os.getenv('SENDER_EMAIL'),
    'sender_password': os.getenv('SENDER_PASSWORD'),
    'recipient_email': os.getenv('RECIPIENT_EMAIL'),
    'use_tls': os.getenv('USE_TLS').lower() == 'true'
}

# Application Configuration
APP_CONFIG = {
    'scan_interval': int(os.getenv('SCAN_INTERVAL')),
    'dashboard_refresh': int(os.getenv('DASHBOARD_REFRESH')),
    'network_cidr': os.getenv('NETWORK_CIDR')
}

# Database Configuration
DB_CONFIG = {
    'uri': os.getenv('DATABASE_URI')
}

# Web Server Configuration
SERVER_CONFIG = {
    'host': os.getenv('FLASK_HOST'),
    'port': int(os.getenv('FLASK_PORT')),
    'debug': os.getenv('FLASK_DEBUG').lower() == 'true',
    'threads': int(os.getenv('WAITRESS_THREADS'))
}

# Logging Configuration
LOG_CONFIG = {
    'file': os.getenv('LOG_FILE'),
    'level': os.getenv('LOG_LEVEL')
} 