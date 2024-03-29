import argparse
import logging
import socket
import errno
from scapy.all import *
import threading

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

open_ports = []

def stealth_scan(dst_ip, dst_port):
    timeout = 3
    max_retries = 3

    for _ in range(max_retries):
        response = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="S"), timeout=timeout, verbose=0)
        if response is None:
            print(f"Port {dst_port} on {dst_ip} is Filtered or Closed")
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                open_ports.append((dst_ip, dst_port))
                print(f"Port {dst_port} on {dst_ip} is Open")
                send(IP(dst=dst_ip)/TCP(dport=dst_port, flags="R"), verbose=0)
                break
            elif response.getlayer(TCP).flags == 0x14:
                print(f"Port {dst_port} on {dst_ip} is Closed")
                break
        else:
            print(f"Port {dst_port} on {dst_ip} is Filtered or Closed")

        if _ < max_retries - 1:
            print("Retrying...")

def null_scan(dst_ip, dst_port):
    null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags=""), timeout=10)
    if str(type(null_scan_resp)) == "<class 'NoneType'>":
        print(f"Port {dst_port} on {dst_ip} is Open")
    elif null_scan_resp.haslayer(TCP):
        if null_scan_resp.getlayer(TCP).flags == 0x14:
            print(f"Port {dst_port} on {dst_ip} is Closed")
    elif null_scan_resp.haslayer(ICMP):
        if int(null_scan_resp.getlayer(ICMP).type) == 3 and int(null_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            print(f"Port {dst_port} on {dst_ip} is Filtered")

def vanilla_scan(dst_ip, dst_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    try:
        s.connect((dst_ip, dst_port))
        s.shutdown(socket.SHUT_WR)
    except socket.error as e:
        if e.errno == errno.ECONNREFUSED:
            print(f"Port {dst_port} on {dst_ip} is Closed")
        elif e.errno == errno.ETIMEDOUT:
            print(f"Port {dst_port} on {dst_ip} is Filtered")
        else:
            print(f"Error: {e}")
    else:
        open_ports.append((dst_ip, dst_port))
        print(f"Port {dst_port} on {dst_ip} is Open")
        s.close()

def scan_worker(ip, port, scan_type):
    print(f"Scanning IP: {ip}, Port: {port}")
    if scan_type == "stealth":
        stealth_scan(ip, port)
    elif scan_type == "null":
        null_scan(ip, port)
    elif scan_type == "vanilla":
        vanilla_scan(ip, port)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Port Scanner")
    parser.add_argument("ip_range", help="Range of IP addresses (start-end)")
    parser.add_argument("port_range", help="Range of port numbers (start-end)")
    parser.add_argument("scan_type", choices=["stealth", "null", "vanilla"], help="Type of scan to perform")
    args = parser.parse_args()

    ip_range = args.ip_range.split("-")
    ip_start = ip_range[0]
    ip_end = ip_range[1]

    port_range = args.port_range.split("-")
    port_start = int(port_range[0])
    port_end = int(port_range[1])

    scan_type = args.scan_type

    ip_prefix = ".".join(ip_start.split(".")[:-1]) + "."
    ip_start_suffix = int(ip_start.split(".")[-1])
    ip_end_suffix = int(ip_end)

    threads = []

    for ip_suffix in range(ip_start_suffix, ip_end_suffix + 1):
        ip = ip_prefix + str(ip_suffix)
        for port in range(port_start, port_end + 1):
            thread = threading.Thread(target=scan_worker, args=(ip, port, scan_type))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    print("Open ports:")
    for ip, port in open_ports:
        print(f"IP: {ip}, Port: {port}")
