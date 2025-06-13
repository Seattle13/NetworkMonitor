# Network Scanner and Monitoring System

A network monitoring solution that scans local Wi-Fi networks, collects device information, stores it in a structured database, and presents it through a web-based dashboard. The system includes real-time alerting capabilities for new device detection.

## Features

- **Network Discovery**: Comprehensive network scanning using Nmap
- **Device Tracking**: Monitor all devices on your network
- **Service Detection**: Identify running services and their versions
- **Vendor Identification**: Automatically detect device manufacturers
- **Real-time Dashboard**: Web-based interface for monitoring
- **Email Alerts**: Instant notifications for new devices
- **Historical Data**: Track device presence over time
- **RESTful API**: Programmatic access to network data

## Prerequisites

- Python 3.8 or higher
- Nmap installed and in system PATH
- SQLite3 (included with Python)
- SMTP server access (for email alerts)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd network-scanner
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Unix or MacOS:
source .venv/bin/activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Configure the application:
   - Copy `config.py.example` to `config.py`
   - Update the configuration settings in `config.py`

## Configuration

The system can be configured through `config.py`. Key settings include:

- Network CIDR range to scan
- Scan interval
- Email alert settings
- Database configuration
- Web application settings

## Usage

### Starting the Application

1. Initialize the database:
```bash
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

2. Start the web application:
```bash
python app.py
```

The dashboard will be available at `http://localhost:5000`

### Running as a Service

For production deployment, the application can be run as a system service:

1. Copy the service file:
```bash
sudo cp network_scanner.service /etc/systemd/system/
```

2. Enable and start the service:
```bash
sudo systemctl enable network_scanner
sudo systemctl start network_scanner
```

### Nginx Configuration

For production deployment with Nginx:

1. Copy the Nginx configuration:
```bash
sudo cp nginx.conf /etc/nginx/sites-available/network_scanner
```

2. Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/network_scanner /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## API Endpoints

The system provides the following RESTful API endpoints:

- `GET /api/hosts`: Retrieve all discovered hosts
- `GET /api/hosts/<ip>`: Get details for a specific host
- `GET /api/services`: List all discovered services
- `GET /api/vendors`: List all detected vendors

## Security Considerations

- The application requires appropriate permissions for Nmap operations
- Email alerts use TLS for secure transmission
- Database access is restricted to local connections
- Web interface should be protected with appropriate authentication

## Troubleshooting

Common issues and solutions:

1. **Nmap Permission Errors**
   - Ensure Nmap is installed and in PATH
   - Run with appropriate permissions (sudo/administrator)

2. **Database Errors**
   - Check database file permissions
   - Verify SQLite installation

3. **Email Alert Issues**
   - Verify SMTP server settings
   - Check email credentials

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License.

## Acknowledgments

- Nmap project for network scanning capabilities
- Flask framework for web interface
- SQLAlchemy for database management 
