from flask import Flask, render_template, jsonify
from database import db, Host, Port, Vendor, Service, MACHistory
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import os
from main import scan_network_and_collect_data, nm
from email_utils import send_alert_email, format_host_alert, format_mac_alert
from config import APP_CONFIG, DB_CONFIG, SERVER_CONFIG, LOG_CONFIG
import logging

# Configure logging first, before anything else
logging.basicConfig(
    filename=LOG_CONFIG['file'],
    level=getattr(logging, LOG_CONFIG['level']),
    format='%(asctime)s %(levelname)s: %(message)s',
    force=True  # Force reconfiguration of logging
)

app = Flask(__name__)

# Ensure database URI is set
if not DB_CONFIG['uri']:
    raise ValueError("Database URI is not configured. Please check your .env file.")

app.config['SQLALCHEMY_DATABASE_URI'] = DB_CONFIG['uri']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Create database tables
with app.app_context():
    db.create_all()
    logging.info("Database initialized and tables created")

def get_or_create_vendor(mac_address, vendor_name):
    """Get or create a vendor record based on MAC address prefix"""
    if not mac_address or not vendor_name:
        return None
    
    mac_prefix = mac_address[:8].upper()  # First 8 chars of MAC
    vendor = Vendor.query.filter_by(mac_prefix=mac_prefix).first()
    if not vendor:
        vendor = Vendor(mac_prefix=mac_prefix, name=vendor_name)
        db.session.add(vendor)
        db.session.flush()
    return vendor

def get_or_create_service(service_name, product, version):
    """Get or create a service record"""
    if not service_name:
        return None
    
    # Create a unique key for the service
    service = Service.query.filter_by(
        name=service_name,
        product=product,
        version=version
    ).first()
    
    if not service:
        service = Service(
            name=service_name,
            product=product,
            version=version
        )
        db.session.add(service)
        db.session.flush()
    return service

def store_scan_results():
    """Store the results of the latest scan in the database"""
    with app.app_context():
        try:
            # Get list of currently known hosts and MAC addresses
            known_hosts = {host.ip_address for host in Host.query.all()}
            known_macs = {mac.mac_address for mac in MACHistory.query.all()}
            logging.info(f"Current known hosts: {len(known_hosts)}")
            logging.info(f"Current known MACs: {len(known_macs)}")
            
            new_hosts = set()
            new_macs = set()
            
            # Get all hosts from nmap scan
            all_hosts = nm.all_hosts()
            logging.info(f"Hosts found in scan: {len(all_hosts)}")
            logging.info(f"Scan results: {all_hosts}")

            for host_ip in all_hosts:
                is_new_host = host_ip not in known_hosts
                if is_new_host:
                    new_hosts.add(host_ip)
                    logging.info(f"New host found: {host_ip}")
                
                # Get or create host
                host = Host.query.filter_by(ip_address=host_ip).first()
                if not host:
                    host = Host(ip_address=host_ip)
                    host.first_seen = datetime.utcnow()
                    logging.info(f"Created new host record for: {host_ip}")
                
                # Update host information
                host.status = nm[host_ip].state()
                host.last_seen = datetime.utcnow()
                logging.info(f"Updated host {host_ip} status: {host.status}")
                
                # Update hostname
                try:
                    host.hostname = nm[host_ip].hostname()
                    logging.info(f"Host {host_ip} hostname: {host.hostname}")
                except KeyError:
                    logging.warning(f"No hostname found for {host_ip}")
                
                # Update MAC and vendor
                if 'addresses' in nm[host_ip] and 'mac' in nm[host_ip]['addresses']:
                    host.mac_address = nm[host_ip]['addresses']['mac']
                    logging.info(f"Host {host_ip} MAC: {host.mac_address}")
                    
                    if host.mac_address in nm[host_ip]['vendor']:
                        vendor_name = nm[host_ip]['vendor'][host.mac_address]
                        vendor = get_or_create_vendor(host.mac_address, vendor_name)
                        host.vendor_id = vendor.id if vendor else None
                        logging.info(f"Host {host_ip} vendor: {vendor_name}")
                
                db.session.add(host)
                db.session.flush()
                
                # Update ports
                for protocol in nm[host_ip].all_protocols():
                    for port_num, port_info in nm[host_ip][protocol].items():
                        port = Port.query.filter_by(
                            host_id=host.id,
                            port_number=port_num,
                            protocol=protocol
                        ).first()
                        
                        if not port:
                            port = Port(
                                host_id=host.id,
                                port_number=port_num,
                                protocol=protocol
                            )
                            logging.info(f"New port found for {host_ip}: {port_num}/{protocol}")
                        
                        port.state = port_info.get('state')
                        logging.info(f"Port {port_num}/{protocol} state: {port.state}")
                        
                        # Create or get service
                        service = get_or_create_service(
                            port_info.get('name'),
                            port_info.get('product'),
                            port_info.get('version')
                        )
                        port.service_id = service.id if service else None
                        port.last_seen = datetime.utcnow()
                        
                        db.session.add(port)
                
                db.session.commit()
                logging.info(f"Successfully stored data for host: {host_ip}")
            
            logging.info(f"Scan results stored. New hosts: {len(new_hosts)}, New MACs: {len(new_macs)}")
            return True
            
        except Exception as e:
            logging.error(f"Error storing scan results: {str(e)}")
            db.session.rollback()
            return False

def run_scan():
    """Run the network scan and store results"""
    logging.info("Starting scheduled scan")
    if scan_network_and_collect_data():
        logging.info("Scan completed successfully, storing results")
        store_scan_results()
    else:
        logging.error("Scan failed")

# Initialize scheduler but don't start it yet
scheduler = BackgroundScheduler()
scheduler.add_job(run_scan, 'interval', minutes=APP_CONFIG['scan_interval'])
logging.info(f"Scheduler configured with interval: {APP_CONFIG['scan_interval']} minutes")

# Run initial scan
logging.info("Running initial scan")
run_scan()

@app.route('/')
def index():
    """Render the main dashboard page"""
    try:
        # Run an initial scan if no hosts are found
        hosts = Host.query.all()
        logging.info(f"Found {len(hosts)} hosts in database")
        
        if not hosts:
            logging.info("No hosts found, running initial scan")
            scan_success = scan_network_and_collect_data()
            logging.info(f"Scan completed with success: {scan_success}")
            
            if scan_success:
                store_success = store_scan_results()
                logging.info(f"Store results completed with success: {store_success}")
                hosts = Host.query.all()
                logging.info(f"After scan and store, found {len(hosts)} hosts")
            else:
                logging.error("Initial scan failed")
        
        return render_template('index.html', hosts=hosts)
    except Exception as e:
        logging.error(f"Error in index route: {str(e)}")
        return render_template('index.html', hosts=[])

@app.route('/api/hosts')
def get_hosts():
    """API endpoint to get all hosts"""
    try:
        hosts = Host.query.all()
        logging.info(f"API request: returning {len(hosts)} hosts")
        
        host_data = [{
            'ip': host.ip_address,
            'mac': host.mac_address,
            'hostname': host.hostname,
            'vendor': host.vendor_info.name if host.vendor_info else None,
            'os': host.os_details,
            'status': host.status,
            'first_seen': host.first_seen.isoformat() if host.first_seen else None,
            'last_seen': host.last_seen.isoformat() if host.last_seen else None,
            'ports': [{
                'number': port.port_number,
                'protocol': port.protocol,
                'state': port.state,
                'service': port.service_info.name if port.service_info else None,
                'product': port.service_info.product if port.service_info else None,
                'version': port.service_info.version if port.service_info else None
            } for port in host.ports]
        } for host in hosts]
        
        return jsonify(host_data)
    except Exception as e:
        logging.error(f"Error in get_hosts API: {str(e)}")
        return jsonify([])

if __name__ == '__main__':
    # Start Flask app
    app.run(
        host=SERVER_CONFIG['host'],
        port=SERVER_CONFIG['port'],
        debug=SERVER_CONFIG['debug']
    ) 