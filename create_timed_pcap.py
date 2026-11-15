from scapy.all import IP, TCP, wrpcap

packets = []
start = 1700000000

# Scenario 1: Rapid scanning
for i, port in enumerate([21,22,23,25,80,110,139,443,445,3389]):
    pkt = IP(src="192.168.1.50", dst="192.168.1.100") / TCP(
        sport=50000+i, dport=port, flags="S"
    )
    pkt.time = start + i
    packets.append(pkt)

# Scenario 2: Connections spread over time
for i, port in enumerate([80,443,8080,8443,22,25]):
    pkt = IP(src="192.168.1.20", dst="192.168.1.100") / TCP(
        sport=51000+i, dport=port, flags="S"
    )
    pkt.time = start + i*120
    packets.append(pkt)

wrpcap("timed_traffic.pcap", packets)
print("Created timed_traffic.pcap with", len(packets), "packets")
