# Network Scanner Deployment Guide for Linux

This guide provides step-by-step instructions for deploying the Network Scanner application on a Linux system.

## Prerequisites

1. **System Requirements**
   - Linux distribution (Ubuntu/Debian recommended)
   - Python 3.8 or higher
   - Nmap installed
   - Nginx (for production deployment)
   - Systemd (for service management)

2. **Install Required System Packages**
   ```bash
   # Update package lists
   sudo apt update

   # Install Python and pip
   sudo apt install python3 python3-pip python3-venv

   # Install Nmap
   sudo apt install nmap

   # Install Nginx (for production)
   sudo apt install nginx
   ```

## Deployment Steps

1. **Clone and Setup the Application**
   ```bash
   # Clone the repository
   git clone <repository-url>
   cd network-scanner

   # Create and activate virtual environment
   python3 -m venv .venv
   source .venv/bin/activate

   # Install Python dependencies
   pip install -r requirements.txt
   ```

2. **Configure Environment Variables**
   ```bash
   # Copy the example environment file
   cp .env.example .env

   # Edit the .env file with your configuration
   nano .env
   ```

3. **Initialize the Database**
   ```bash
   # Create database tables
   python3 -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

4. **Configure Nginx**
   ```bash
   # Copy the Nginx configuration
   sudo cp nginx.conf /etc/nginx/sites-available/network_scanner

   # Create symbolic link
   sudo ln -s /etc/nginx/sites-available/network_scanner /etc/nginx/sites-enabled/

   # Test Nginx configuration
   sudo nginx -t

   # Restart Nginx
   sudo systemctl restart nginx
   ```

5. **Setup Systemd Service**
   ```bash
   # Edit the service file
   sudo nano /etc/systemd/system/network_scanner.service
   ```

   Update the service file with your specific paths:
   ```ini
   [Unit]
   Description=Network Scanner Web Application
   After=network.target

   [Service]
   User=YOUR_USERNAME
   Group=YOUR_GROUP
   WorkingDirectory=/path/to/network-scanner
   Environment="PATH=/path/to/network-scanner/.venv/bin"
   ExecStart=/path/to/network-scanner/.venv/bin/python wsgi.py
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

   Enable and start the service:
   ```bash
   # Reload systemd
   sudo systemctl daemon-reload

   # Enable the service
   sudo systemctl enable network_scanner

   # Start the service
   sudo systemctl start network_scanner
   ```

6. **Verify Deployment**
   ```bash
   # Check service status
   sudo systemctl status network_scanner

   # Check Nginx status
   sudo systemctl status nginx

   # Check logs
   sudo journalctl -u network_scanner
   ```

## Security Considerations

1. **Firewall Configuration**
   ```bash
   # Allow HTTP/HTTPS traffic
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp

   # Enable firewall
   sudo ufw enable
   ```

2. **SSL/TLS Setup (Recommended)**
   ```bash
   # Install Certbot
   sudo apt install certbot python3-certbot-nginx

   # Obtain SSL certificate
   sudo certbot --nginx -d your-domain.com
   ```

3. **File Permissions**
   ```bash
   # Set proper permissions for the application directory
   sudo chown -R YOUR_USERNAME:YOUR_GROUP /path/to/network-scanner
   sudo chmod -R 755 /path/to/network-scanner
   ```

## Maintenance

1. **Updating the Application**
   ```bash
   # Pull latest changes
   git pull

   # Update dependencies
   source .venv/bin/activate
   pip install -r requirements.txt

   # Restart the service
   sudo systemctl restart network_scanner
   ```

2. **Monitoring Logs**
   ```bash
   # View application logs
   sudo journalctl -u network_scanner -f

   # View Nginx logs
   sudo tail -f /var/log/nginx/network_scanner_access.log
   sudo tail -f /var/log/nginx/network_scanner_error.log
   ```

3. **Database Backup**
   ```bash
   # Create backup directory
   mkdir -p /path/to/backups

   # Backup database
   sqlite3 network_scan.db .dump > /path/to/backups/backup_$(date +%Y%m%d).sql
   ```

## Troubleshooting

1. **Service Won't Start**
   - Check service status: `sudo systemctl status network_scanner`
   - Check logs: `sudo journalctl -u network_scanner`
   - Verify environment variables in `.env`
   - Check file permissions

2. **Nginx Issues**
   - Check Nginx status: `sudo systemctl status nginx`
   - Check Nginx logs: `sudo tail -f /var/log/nginx/error.log`
   - Verify Nginx configuration: `sudo nginx -t`

3. **Database Issues**
   - Check database file permissions
   - Verify database connection string in `.env`
   - Check for disk space issues

4. **Network Scanner Issues**
   - Verify Nmap installation: `nmap --version`
   - Check Nmap permissions
   - Verify network CIDR configuration in `.env`

## Support

For additional support:
1. Check the application logs
2. Review the documentation
3. Check the GitHub repository issues
4. Contact the development team 