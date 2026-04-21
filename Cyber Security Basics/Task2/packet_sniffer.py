from scapy.all import sniff
from collections import Counter
import matplotlib.pyplot as plt

protocols = []

def packet_callback(packet):
    if packet.haslayer("TCP"):
        protocols.append("TCP")
    elif packet.haslayer("UDP"):
        protocols.append("UDP")
    elif packet.haslayer("ICMP"):
        protocols.append("ICMP")
    else:
        protocols.append("Other")

# Capture 100 packets
print("[*] Sniffing packets...")
sniff(count=100, prn=packet_callback)

# Count protocols
proto_count = Counter(protocols)
print("\nProtocol Distribution:")
for proto, count in proto_count.items():
    print(f"{proto}: {count}")

# Plot bar chart
plt.bar(proto_count.keys(), proto_count.values())
plt.xlabel("Protocols")
plt.ylabel("Packet Count")
plt.title("Protocol Distribution")
plt.show()
