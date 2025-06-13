import nmap
from config import APP_CONFIG

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

    print(f"[*] Starting network scan on: {network_cidr}")
    print("[*] This process can take several minutes depending on the network size and scan intensity.")
    print("[*] Ensure Nmap is installed and you have necessary permissions for the chosen scan type.")

    # --- Nmap Scan Arguments ---
    # -sS: TCP SYN scan (stealthy, efficient, often requires root/admin privileges).
    # -sV: Probe open ports to determine service/version info.
    # -O: Enable OS detection (often requires root/admin privileges).
    # -T4: Timing template (aggressive, for faster scans).
    # --host-timeout 10m: Abort scanning a single host if it takes longer than 10 minutes.
    #
    # Common alternatives if -sS or -O cause permission issues:
    #   arguments = '-sT -sV -T4 --host-timeout 5m' # TCP Connect scan (doesn't need root, but slower and more detectable)
    #   arguments = '-T4 -F --open' # Fast scan of common ports, shows open ones (quicker, less info)
    #   arguments = '-sn' # Ping scan (host discovery only, no port info - formerly -sP)
    #
    # For this initial script, we'll aim for a comprehensive scan.
    # If issues arise, switch to simpler arguments.
    scan_arguments = '-sS -sV -O -T4 --host-timeout 10m'
    # scan_arguments = '-sT -sV -T4 --host-timeout 5m' # Fallback if no root access

    try:
        # The scan method populates the 'nm' instance with results.
        print(f"[*] Executing Nmap with arguments: {scan_arguments}")
        nm.scan(hosts=network_cidr, arguments=scan_arguments)
        print("[+] Nmap scan command executed. Results are being processed by python-nmap.")
        return True
    except nmap.PortScannerError as e:
        print(f"[!] Nmap Execution Error: {e}")
        print("[!] Please ensure Nmap is installed and in your system's PATH.")
        print(
            "[!] For scan types like -sS (TCP SYN) or -O (OS Detection), you might need to run this script with sudo/administrator privileges.")
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred during Nmap scan initiation: {e}")
        return False


if __name__ == "__main__":
    if scan_network_and_collect_data():
        # display_collected_host_data()
        pass
    else:
        print("[!] Scan could not be completed. Please check error messages and configurations.")

