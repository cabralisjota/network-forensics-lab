from scapy.all import rdpcap, IP, TCP, UDP, DNSQR
from collections import Counter

packets = rdpcap("training.pcap")

protocols = Counter()
source_ips = Counter()
destination_ips = Counter()

print("\n=== NETWORK FORENSICS LAB ===")
print("Total packets:", len(packets))

for number, packet in enumerate(packets, 1):

    print(f"\n--- Packet {number} ---")

    if IP not in packet:
        continue

    source = packet[IP].src
    destination = packet[IP].dst

    source_ips[source] += 1
    destination_ips[destination] += 1

    print("Source:", source)
    print("Destination:", destination)

    if TCP in packet:
        protocols["TCP"] += 1
        print("Protocol: TCP")
        print("Destination port:", packet[TCP].dport)
        print("TCP flags:", packet[TCP].flags)

    elif UDP in packet:
        protocols["UDP"] += 1
        print("Protocol: UDP")
        print("Destination port:", packet[UDP].dport)

    if DNSQR in packet:
        print("DNS query:", packet[DNSQR].qname.decode())

print("\n=== ANALYSIS SUMMARY ===")

print("\nProtocols:")
for protocol, count in protocols.items():
    print(f"{protocol}: {count}")

print("\nTop source IPs:")
for ip, count in source_ips.most_common():
    print(f"{ip}: {count} packets")

print("\nTop destination IPs:")
for ip, count in destination_ips.most_common():
    print(f"{ip}: {count} packets")
