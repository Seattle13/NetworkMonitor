from waitress import serve
from app import app, db, scheduler
from config import SERVER_CONFIG, LOG_CONFIG
import logging

# Configure logging
logging.basicConfig(
    filename=LOG_CONFIG['file'],
    level=getattr(logging, LOG_CONFIG['level']),
    format='%(asctime)s %(levelname)s: %(message)s'
)

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    
    # Start the scheduler
    scheduler.start()
    
    # Start the Waitress server
    logging.info('Starting Waitress server...')
    serve(
        app,
        host=SERVER_CONFIG['host'],
        port=SERVER_CONFIG['port'],
        threads=SERVER_CONFIG['threads']
    ) 