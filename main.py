import nmap
from config import APP_CONFIG
import logging
from database import db, update_host_and_ports_from_scan

# Global PortScanner instance.
# The python-nmap library often uses the instance to store and access scan results.
nm = nmap.PortScanner()


def scan_network_and_collect_data(network_cidr=None):
    """
    Scans the specified network CIDR using Nmap and collects host information.
    The results are stored in the global 'nm' PortScanner instance.

    Args:
        network_cidr (str): The network to scan in CIDR notation (e.g., '192.168.1.0/24').
                           If None, uses the default from configuration.

    Returns:
        bool: True if the scan was initiated successfully (results are in 'nm'),
              False if Nmap execution error occurred.
    """
    if network_cidr is None:
        network_cidr = APP_CONFIG['network_cidr']

    logging.info(f"Starting network scan on: {network_cidr}")
    print("[*] This process can take several minutes depending on the network size and scan intensity.")
    print("[*] Ensure Nmap is installed and you have necessary permissions for the chosen scan type.")

    # Using scan arguments that include MAC address detection
    scan_arguments = '-sT -A -T4 --host-timeout 5m'  # Added -PR for MAC detection

    try:
        logging.info(f"Executing Nmap with arguments: {scan_arguments}")
        nm.scan(hosts=network_cidr, arguments=scan_arguments)
        
        # Log scan results
        hosts = nm.all_hosts()
        logging.info(f"Scan completed. Found {len(hosts)} hosts")
        for host in hosts:
            logging.info(f"Host {host}: {nm[host].state()}")
            if 'addresses' in nm[host]:
                logging.info(f"MAC: {nm[host]['addresses'].get('mac', 'N/A')}")
            if 'osmatch' in nm[host]:
                logging.info(f"OS: {nm[host]['osmatch'][0]['name'] if nm[host]['osmatch'] else 'N/A'}")
        
        return True
    except nmap.PortScannerError as e:
        logging.error(f"Nmap Execution Error: {e}")
        print("[!] Please ensure Nmap is installed and in your system's PATH.")
        print(
            "[!] For scan types like -sS (TCP SYN) or -O (OS Detection), you might need to run this script with sudo/administrator privileges.")
        return False
    except Exception as e:
        logging.error(f"Unexpected error during scan: {e}")
        return False


if __name__ == "__main__":
    if scan_network_and_collect_data():
        # Update database with scan results
        try:
            update_host_and_ports_from_scan(nm, db.session)
            logging.info("Successfully updated database with scan results")
        except Exception as e:
            logging.error(f"Error updating database: {e}")
            print("[!] Error updating database with scan results. Check logs for details.")
    else:
        print("[!] Scan could not be completed. Please check error messages and configurations.")

