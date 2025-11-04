#!/usr/bin/env python3
"""
Network Scanner Tool
Scans local network for active devices using ARP requests
"""

import scapy.all as scapy
import argparse
from tabulate import tabulate
from colorama import Fore, Style, init
import json
from datetime import datetime

# Initialize colorama
init(autoreset=True)

def get_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Network Scanner - Discover devices on your network")
    parser.add_argument("-t", "--target", dest="target", required=True, 
                        help="Target IP address or IP range (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", dest="output", 
                        help="Save results to file (JSON format)")
    return parser.parse_args()

def scan_network(ip_range):
    """
    Scan network for active devices using ARP requests
    
    Args:
        ip_range (str): IP address or range to scan (e.g., '192.168.1.0/24')
    
    Returns:
        list: List of dictionaries containing IP and MAC addresses
    """
    print(f"\n{Fore.CYAN}[*] Scanning network: {ip_range}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Please wait...{Style.RESET_ALL}\n")
    
    # Create ARP request packet
    arp_request = scapy.ARP(pdst=ip_range)
    
    # Create Ethernet broadcast packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Combine ARP request with Ethernet frame
    arp_request_broadcast = broadcast / arp_request
    
    # Send packet and receive response
    # srp() sends and receives packets at layer 2
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    # Parse responses
    devices = []
    for element in answered_list:
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        }
        devices.append(device_info)
    
    return devices

def display_results(devices):
    """
    Display scan results in a formatted table
    
    Args:
        devices (list): List of device dictionaries
    """
    if not devices:
        print(f"{Fore.RED}[!] No devices found on the network{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[+] Found {len(devices)} device(s) on the network:{Style.RESET_ALL}\n")
    
    # Prepare data for tabulate
    table_data = []
    for idx, device in enumerate(devices, 1):
        table_data.append([idx, device['ip'], device['mac']])
    
    # Display table
    headers = ["#", "IP Address", "MAC Address"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

def save_results(devices, filename):
    """
    Save scan results to JSON file
    
    Args:
        devices (list): List of device dictionaries
        filename (str): Output filename
    """
    output_data = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_devices": len(devices),
        "devices": devices
    }
    
    with open(filename, 'w') as f:
        json.dump(output_data, f, indent=4)
    
    print(f"\n{Fore.GREEN}[+] Results saved to: {filename}{Style.RESET_ALL}")

def main():
    """Main execution function"""
    print(f"{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}{'Network Scanner Tool':^60}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    # Get command line arguments
    args = get_arguments()
    
    # Scan network
    devices = scan_network(args.target)
    
    # Display results
    display_results(devices)
    
    # Save to file if requested
    if args.output:
        save_results(devices, args.output)
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Scan completed successfully!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
