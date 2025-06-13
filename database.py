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