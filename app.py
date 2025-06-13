from flask import Flask, render_template, jsonify
from database import db, Host, Port, Vendor, Service, MACHistory
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
import os
from main import scan_network_and_collect_data, nm
from email_utils import send_alert_email, format_host_alert, format_mac_alert
from config import APP_CONFIG, DB_CONFIG, SERVER_CONFIG, LOG_CONFIG
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DB_CONFIG['uri']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure logging
logging.basicConfig(
    filename=LOG_CONFIG['file'],
    level=getattr(logging, LOG_CONFIG['level']),
    format='%(asctime)s %(levelname)s: %(message)s'
)

db.init_app(app)

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
        # Get list of currently known hosts and MAC addresses
        known_hosts = {host.ip_address for host in Host.query.all()}
        known_macs = {mac.mac_address for mac in MACHistory.query.all()}
        new_hosts = set()
        new_macs = set()

        for host_ip in nm.all_hosts():
            is_new_host = host_ip not in known_hosts
            if is_new_host:
                new_hosts.add(host_ip)
            
            # Get or create host
            host = Host.query.filter_by(ip_address=host_ip).first()
            if not host:
                host = Host(ip_address=host_ip)
                host.first_seen = datetime.utcnow()  # Set first seen time for new hosts
            
            # Update host information
            host.status = nm[host_ip].state()
            host.last_seen = datetime.utcnow()
            
            # Update hostname
            try:
                host.hostname = nm[host_ip].hostname()
            except KeyError:
                pass
            
            # Update MAC and vendor
            if 'addresses' in nm[host_ip] and 'mac' in nm[host_ip]['addresses']:
                host.mac_address = nm[host_ip]['addresses']['mac']
                if host.mac_address in nm[host_ip]['vendor']:
                    vendor_name = nm[host_ip]['vendor'][host.mac_address]
                    vendor = get_or_create_vendor(host.mac_address, vendor_name)
                    host.vendor_id = vendor.id if vendor else None
                
                # Check if this is a new MAC address
                if host.mac_address and host.mac_address not in known_macs:
                    new_macs.add(host.mac_address)
                    # Create MAC history record
                    mac_history = MACHistory(
                        mac_address=host.mac_address,
                        vendor_id=vendor.id if vendor else None
                    )
                    db.session.add(mac_history)
                    db.session.flush()
                    
                    # Send MAC-based alert
                    subject = f"New Device Detected: {host.mac_address}"
                    message = format_mac_alert(mac_history)
                    send_alert_email(subject, message)
                    logging.info(f"New MAC address detected and alert sent: {host.mac_address}")
            
            # Update OS details
            if 'osmatch' in nm[host_ip] and nm[host_ip]['osmatch']:
                os_match = nm[host_ip]['osmatch'][0]
                host.os_details = f"{os_match['name']} (Accuracy: {os_match['accuracy']}%)"
            
            db.session.add(host)
            db.session.flush()  # Get the host ID
            
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
                    
                    port.state = port_info.get('state')
                    
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

            # Send alert for new hosts
            if is_new_host:
                subject = f"New Host Detected: {host_ip}"
                message = format_host_alert(host)
                send_alert_email(subject, message)
                logging.info(f"New host detected and alert sent: {host_ip}")

def run_scan():
    """Run the network scan and store results"""
    if scan_network_and_collect_data():
        store_scan_results()

# Set up the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(run_scan, 'interval', minutes=APP_CONFIG['scan_interval'])
scheduler.start()

@app.route('/')
def index():
    """Render the main dashboard page"""
    hosts = Host.query.all()
    return render_template('index.html', hosts=hosts)

@app.route('/api/hosts')
def get_hosts():
    """API endpoint to get all hosts"""
    hosts = Host.query.all()
    return jsonify([{
        'ip': host.ip_address,
        'mac': host.mac_address,
        'hostname': host.hostname,
        'vendor': host.vendor_info.name if host.vendor_info else None,
        'os': host.os_details,
        'status': host.status,
        'first_seen': host.first_seen.isoformat(),
        'last_seen': host.last_seen.isoformat(),
        'ports': [{
            'number': port.port_number,
            'protocol': port.protocol,
            'state': port.state,
            'service': port.service_info.name if port.service_info else None,
            'product': port.service_info.product if port.service_info else None,
            'version': port.service_info.version if port.service_info else None
        } for port in host.ports]
    } for host in hosts])

if __name__ == '__main__':
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Run initial scan
    run_scan()
    
    # Start Flask app
    app.run(
        host=SERVER_CONFIG['host'],
        port=SERVER_CONFIG['port'],
        debug=SERVER_CONFIG['debug']
    ) 