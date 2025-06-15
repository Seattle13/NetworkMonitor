from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Vendor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_prefix = db.Column(db.String(8), unique=True, nullable=False)  # First 8 chars of MAC
    name = db.Column(db.String(255), nullable=False)
    hosts = db.relationship('Host', backref='vendor_info', lazy=True)

    def __repr__(self):
        return f'<Vendor {self.name}>'

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    product = db.Column(db.String(255))
    version = db.Column(db.String(255))
    ports = db.relationship('Port', backref='service_info', lazy=True)

    def __repr__(self):
        return f'<Service {self.name}>'

class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), nullable=False)
    mac_address = db.Column(db.String(17))
    hostname = db.Column(db.String(255))
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'))
    os_details = db.Column(db.String(255))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)  # When host was first detected
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)   # When host was last seen
    status = db.Column(db.String(20))
    ports = db.relationship('Port', backref='host', lazy=True)

    def __repr__(self):
        return f'<Host {self.ip_address}>'

class Port(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(4), nullable=False)
    state = db.Column(db.String(20))
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Port {self.port_number}/{self.protocol}>'

class MACHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mac_address = db.Column(db.String(17), nullable=False, unique=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendor.id'))
    vendor_info = db.relationship('Vendor', backref='mac_history', lazy=True)

    def __repr__(self):
        return f'<MACHistory {self.mac_address}>'

class ChangeHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    change_type = db.Column(db.String(50), nullable=False)  # 'host_status', 'port_status', 'new_host', etc.
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'))
    host = db.relationship('Host', backref='changes')
    details = db.Column(db.Text)  # JSON string containing change details
    notified = db.Column(db.Boolean, default=False)  # Whether email notification was sent

    def __repr__(self):
        return f'<ChangeHistory {self.change_type} at {self.timestamp}>'

def update_host_and_ports_from_scan(scan_results, db_session):
    """
    Updates the database with the latest scan results, comparing with existing data
    to update host states and port information.
    
    Args:
        scan_results: The nmap PortScanner instance containing scan results
        db_session: SQLAlchemy database session
    """
    current_time = datetime.utcnow()
    changes_to_notify = []
    
    # Process each host from scan results
    for host_ip in scan_results.all_hosts():
        host_data = scan_results[host_ip]
        
        # Get or create host record
        host = db_session.query(Host).filter_by(ip_address=host_ip).first()
        if not host:
            host = Host(
                ip_address=host_ip,
                first_seen=current_time,
                last_seen=current_time,
                status='up'
            )
            db_session.add(host)
            db_session.flush()  # Get the host ID
            
            # Record new host
            change = ChangeHistory(
                change_type='new_host',
                host_id=host.id,
                details=f'New host discovered: {host_ip}'
            )
            db_session.add(change)
            changes_to_notify.append(change)
        else:
            old_status = host.status
            host.last_seen = current_time
            host.status = 'up'
            
            # Record status change if applicable
            if old_status != 'up':
                change = ChangeHistory(
                    change_type='host_status',
                    host_id=host.id,
                    details=f'Host status changed from {old_status} to up'
                )
                db_session.add(change)
                changes_to_notify.append(change)
        
        # Update MAC address if available
        if 'addresses' in host_data and 'mac' in host_data['addresses']:
            old_mac = host.mac_address
            new_mac = host_data['addresses']['mac']
            if old_mac != new_mac:
                host.mac_address = new_mac
                change = ChangeHistory(
                    change_type='mac_change',
                    host_id=host.id,
                    details=f'MAC address changed from {old_mac} to {new_mac}'
                )
                db_session.add(change)
                changes_to_notify.append(change)
        
        # Update OS information if available
        if 'osmatch' in host_data and host_data['osmatch']:
            old_os = host.os_details
            new_os = host_data['osmatch'][0]['name']
            if old_os != new_os:
                host.os_details = new_os
                change = ChangeHistory(
                    change_type='os_change',
                    host_id=host.id,
                    details=f'OS changed from {old_os} to {new_os}'
                )
                db_session.add(change)
                changes_to_notify.append(change)
        
        # Get existing ports for comparison
        existing_ports = {(p.port_number, p.protocol): p for p in host.ports}
        
        # Process TCP ports
        if 'tcp' in host_data:
            for port_num, port_data in host_data['tcp'].items():
                port_key = (int(port_num), 'tcp')
                old_port = existing_ports.get(port_key)
                
                if old_port:
                    if old_port.state != port_data['state']:
                        change = ChangeHistory(
                            change_type='port_status',
                            host_id=host.id,
                            details=f'Port {port_num}/tcp state changed from {old_port.state} to {port_data["state"]}'
                        )
                        db_session.add(change)
                        changes_to_notify.append(change)
                    existing_ports.pop(port_key)
                else:
                    change = ChangeHistory(
                        change_type='new_port',
                        host_id=host.id,
                        details=f'New port discovered: {port_num}/tcp ({port_data["state"]})'
                    )
                    db_session.add(change)
                    changes_to_notify.append(change)
                
                # Create or update port
                port = Port(
                    host_id=host.id,
                    port_number=port_num,
                    protocol='tcp',
                    state=port_data['state'],
                    last_seen=current_time
                )
                
                # Add service information if available
                if 'name' in port_data and port_data['name'] != '':
                    service = db_session.query(Service).filter_by(
                        name=port_data['name']
                    ).first()
                    
                    if not service:
                        service = Service(
                            name=port_data['name'],
                            product=port_data.get('product', ''),
                            version=port_data.get('version', '')
                        )
                        db_session.add(service)
                    
                    port.service_id = service.id
                
                db_session.add(port)
        
        # Record closed/removed ports
        for (port_num, protocol), old_port in existing_ports.items():
            change = ChangeHistory(
                change_type='port_closed',
                host_id=host.id,
                details=f'Port {port_num}/{protocol} is no longer open (was {old_port.state})'
            )
            db_session.add(change)
            changes_to_notify.append(change)
            db_session.delete(old_port)
    
    # Mark hosts that weren't found in the scan as down
    current_hosts = set(scan_results.all_hosts())
    all_hosts = db_session.query(Host).all()
    for host in all_hosts:
        if host.ip_address not in current_hosts and host.status != 'down':
            host.status = 'down'
            change = ChangeHistory(
                change_type='host_status',
                host_id=host.id,
                details=f'Host status changed from up to down'
            )
            db_session.add(change)
            changes_to_notify.append(change)
    
    # Commit all changes
    db_session.commit()
    
    return changes_to_notify 