import pyshark
import matplotlib.pyplot as plt
from collections import Counter
from typing import List

# Load capture file
capture = pyshark.FileCapture('traffic.pcapng', display_filter='tcp.port == 443')

packet_sizes: List[int] = []
src_ips: List[str] = []
dst_ips: List[str] = []

# Parse packets
for packet in capture:
    try:
        size = int(packet.length)
        src = packet.ip.src
        dst = packet.ip.dst

        packet_sizes.append(size)
        src_ips.append(src)
        dst_ips.append(dst)

    except AttributeError:
        continue

capture.close()

# Count packets per IP
src_count = Counter(src_ips)
dst_count = Counter(dst_ips)

# Print summary
print("\nTop Source IPs:")
for ip, count in src_count.most_common(5):
    print(f"{ip}: {count}")

print("\nTop Destination IPs:")
for ip, count in dst_count.most_common(5):
    print(f"{ip}: {count}")

# Plot packet size distribution
plt.hist(packet_sizes, bins=20)
plt.title("Packet Size Distribution")
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.show()
