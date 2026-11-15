from scapy.all import IP, TCP, wrpcap

packets = []
base_time = 1700000000.0

# One NULL-flag packet
pkt = IP(src="10.10.10.5", dst="10.10.10.10") / TCP(
    sport=40000, dport=80, flags=0
)
pkt.time = base_time
packets.append(pkt)

# 110 initial SYN packets within 11 seconds
for i in range(110):
    pkt = IP(
        src="10.10.10.20",
        dst="10.10.10.30"
    ) / TCP(
        sport=40000 + i,
        dport=443,
        flags="S",
        seq=i + 1
    )
    pkt.time = base_time + 1 + i * 0.1
    packets.append(pkt)

wrpcap("ids_test.pcap", packets)

print("Created ids_test.pcap")
print("Total packets:", len(packets))
