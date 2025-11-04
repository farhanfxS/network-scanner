# 🔐 Network Scanner Tool

A beginner-friendly Python-based network security tool for discovering devices and scanning ports on your local network.

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

## ✨ Features

- 🌐 **Network Discovery**: Scan local networks using ARP requests
- 🔍 **Port Scanning**: Fast multi-threaded port scanning
- 📊 **Clean Output**: Formatted tables with color-coded results
- 💾 **Export Results**: Save scan results to JSON format
- ⚡ **Fast Performance**: Concurrent scanning with thread pools
- 🎨 **User-Friendly**: Colorful CLI interface

## 🚀 Installation

# Make scripts executable
chmod +x src/network_scanner.py
chmod +x src/port_scanner.py

# Test network scan (requires sudo)
sudo python3 src/network_scanner.py -t (target ip)

# Test on scanme.nmap.org (legal test server)
python3 src/port_scanner.py -t scanme.nmap.org -p 1-1000

# Test on localhost
python3 src/port_scanner.py -t 127.0.0.1 -p 1-100


### Prerequisites

- Python 3.8 or higher
- Linux/Unix system (Kali Linux recommended)
- Root privileges (for ARP scanning)

### Setup

