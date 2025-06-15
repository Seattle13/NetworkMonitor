from waitress import serve
from app import app, db, scheduler, run_scan
from config import SERVER_CONFIG, LOG_CONFIG
import logging

# Configure logging
logging.basicConfig(
    filename=LOG_CONFIG['file'],
    level=getattr(logging, LOG_CONFIG['level']),
    format='%(asctime)s %(levelname)s: %(message)s',
    force=True
)

if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
        logging.info("Database tables created/verified")
    
    # Start the scheduler if it's not already running
    if not scheduler.running:
        scheduler.start()
        logging.info('Scheduler started')
    
    # Run initial scan
    logging.info("Running initial scan from wsgi")
    run_scan()
    
    # Start the Waitress server
    logging.info('Starting Waitress server...')
    serve(
        app,
        host=SERVER_CONFIG['host'],
        port=SERVER_CONFIG['port'],
        threads=SERVER_CONFIG['threads']
    ) 