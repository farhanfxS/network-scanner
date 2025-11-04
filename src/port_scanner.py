#!/usr/bin/env python3
"""
Port Scanner Tool
Scans specified ports on a target host
"""

import socket
import argparse
from datetime import datetime
from colorama import Fore, Style, init
from tabulate import tabulate
import concurrent.futures

# Initialize colorama
init(autoreset=True)

def get_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Port Scanner - Scan open ports on target host")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", dest="ports", default="1-1000",
                        help="Port range to scan (e.g., 1-1000 or 80,443,8080)")
    parser.add_argument("-th", "--threads", dest="threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    return parser.parse_args()

def parse_ports(port_string):
    """
    Parse port string into list of ports
    
    Args:
        port_string (str): Port range or comma-separated ports
    
    Returns:
        list: List of port numbers to scan
    """
    ports = []
    
    if '-' in port_string:
        # Port range (e.g., "1-1000")
        start, end = port_string.split('-')
        ports = list(range(int(start), int(end) + 1))
    else:
        # Comma-separated ports (e.g., "80,443,8080")
        ports = [int(p.strip()) for p in port_string.split(',')]
    
    return ports

def scan_port(target, port):
    """
    Scan a single port on target host
    
    Args:
        target (str): Target IP or hostname
        port (int): Port number to scan
    
    Returns:
        dict: Port information if open, None otherwise
    """
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        # Attempt connection
        result = sock.connect_ex((target, port))
        
        if result == 0:
            # Port is open, try to get service name
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            
            sock.close()
            return {"port": port, "status": "OPEN", "service": service}
        
        sock.close()
        return None
        
    except socket.gaierror:
        return None
    except socket.error:
        return None

def scan_ports(target, ports, threads=100):
    """
    Scan multiple ports using thread pool
    
    Args:
        target (str): Target IP or hostname
        ports (list): List of ports to scan
        threads (int): Number of concurrent threads
    
    Returns:
        list: List of open ports
    """
    open_ports = []
    
    print(f"{Fore.YELLOW}[*] Scanning {len(ports)} ports...{Style.RESET_ALL}\n")
    
    # Use ThreadPoolExecutor for concurrent scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all port scan tasks
        future_to_port = {executor.submit(scan_port, target, port): port for port in ports}
        
        # Process completed scans
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"{Fore.GREEN}[+] Port {result['port']:<5} - {result['status']:<6} - {result['service']}{Style.RESET_ALL}")
    
    return open_ports

def display_results(target, open_ports, scan_time):
    """
    Display scan results summary
    
    Args:
        target (str): Target host
        open_ports (list): List of open port dictionaries
        scan_time (float): Time taken for scan
    """
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Scan completed in {scan_time:.2f} seconds{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Found {len(open_ports)} open port(s) on {target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    if open_ports:
        # Prepare table data
        table_data = [[p['port'], p['status'], p['service']] for p in sorted(open_ports, key=lambda x: x['port'])]
        headers = ["Port", "Status", "Service"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

def main():
    """Main execution function"""
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}{'Port Scanner Tool':^60}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    # Get arguments
    args = get_arguments()
    
    # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"{Fore.CYAN}[*] Target: {args.target} ({target_ip}){Style.RESET_ALL}")
    except socket.gaierror:
        print(f"{Fore.RED}[!] Error: Could not resolve hostname{Style.RESET_ALL}")
        return
    
    # Parse ports
    ports = parse_ports(args.ports)
    print(f"{Fore.CYAN}[*] Scanning {len(ports)} port(s){Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")
    
    # Scan ports
    start_time = datetime.now()
    open_ports = scan_ports(target_ip, ports, args.threads)
    end_time = datetime.now()
    
    scan_duration = (end_time - start_time).total_seconds()
    
    # Display results
    display_results(target_ip, open_ports, scan_duration)
    
    print()

if __name__ == "__main__":
    main()
