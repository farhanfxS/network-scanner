#!/usr/bin/env python3
"""
Utility functions for network scanner
"""

import re
import socket

def validate_ip(ip_address):
    """
    Validate IP address format
    
    Args:
        ip_address (str): IP address to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip_address):
        octets = ip_address.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    return False

def validate_ip_range(ip_range):
    """
    Validate IP range format (CIDR notation)
    
    Args:
        ip_range (str): IP range in CIDR notation
    
    Returns:
        bool: True if valid, False otherwise
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    return bool(re.match(pattern, ip_range))

def get_local_ip():
    """
    Get local machine's IP address
    
    Returns:
        str: Local IP address
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

