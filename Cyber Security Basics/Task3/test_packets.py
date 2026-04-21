"""
test_packets.py

This script generates TCP SYN packets to simulate a port scan.
Used for testing Snort IDS rules.

Author: Jai Agrawal
"""

from scapy.all import IP, TCP, send
from typing import List


def generate_syn_packets(target_ip: str, ports: List[int]) -> None:
    """
    Generate SYN packets to multiple ports.

    :param target_ip: Target IP address
    :param ports: List of ports to scan
    """
    for port in ports:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(packet, verbose=False)
        print(f"[+] Sent SYN packet to {target_ip}:{port}")


def main() -> None:
    """
    Main function to simulate a port scan.
    """
    target_ip = "192.168.204.130"  # Localhost testing
    ports = list(range(20, 100))  # Scan ports 20–100

    print("[*] Starting SYN scan simulation...")
    generate_syn_packets(target_ip, ports)
    print("[*] Scan completed.")


if __name__ == "__main__":
    main()
