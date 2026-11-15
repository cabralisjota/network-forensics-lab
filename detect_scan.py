from scapy.all import rdpcap, IP, TCP
from collections import defaultdict

packets = rdpcap("port_scan.pcap")

# Group ports by source and destination IP
connections = defaultdict(set)

for packet in packets:
    if IP not in packet or TCP not in packet:
        continue

    tcp = packet[TCP]

    # SYN set, ACK not set
    if tcp.flags & 0x02 and not tcp.flags & 0x10:
        source = packet[IP].src
        target = packet[IP].dst

        connections[(source, target)].add(tcp.dport)

print("\n=== NETWORK THREAT DETECTION ===")
print("Packets analyzed:", len(packets))

THRESHOLD = 5

for (source, target), ports in connections.items():
    print("\nSource:", source)
    print("Target:", target)
    print("Unique ports:", len(ports))
    print("Ports:", sorted(ports))

    if len(ports) >= THRESHOLD:
        print("[ALERT] Possible TCP port scan!")
        print("Severity: MEDIUM")
    else:
        print("No scan threshold reached.")
