# Python Port Scanner

This Python script provides a versatile port scanning tool capable of conducting stealth, null, or vanilla scans across specified IP address and port ranges. It utilizes multithreading for enhanced efficiency, enabling simultaneous scanning of multiple IP addresses and ports.

## Features

- **Stealth Scan:** Conducts TCP SYN scans to identify open ports.
- **Null Scan:** Sends TCP packets with no flags set to infer port states.
- **Vanilla Scan:** Establishes TCP connections to determine port status.
- **Command-Line Interface:** Easily configurable via command-line arguments.
- **Threading:** Optimized for efficiency by scanning multiple IPs and ports concurrently.

## Usage

1. Clone the repository: `git clone https://github.com/username/python-port-scanner.git`
2. Navigate to the project directory: `cd python-port-scanner`
3. Run the script with desired arguments:

## Give cmd like
python port_scanner.py <ip_range> <port_range> <scan_type>
ex-python port_scanner.py 192.168.0.1-192.168.0.10 1-1000 stealth

## Contributors

- [Suhas H S](https://github.com/Suhas-30)

## Disclaimer
This tool is intended for educational and ethical testing purposes only. Any misuse or illegal activities using this tool are strictly prohibited. The author shall not be responsible for any misuse or damage caused by this tool.


