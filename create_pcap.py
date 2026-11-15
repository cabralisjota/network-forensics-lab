from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap

packets = [
    IP(src="192.168.1.10", dst="8.8.8.8") /
    UDP(sport=53000, dport=53) /
    DNS(rd=1, qd=DNSQR(qname="example.com")),

    IP(src="192.168.1.10", dst="93.184.215.14") /
    TCP(sport=51542, dport=80, flags="S"),

    IP(src="192.168.1.10", dst="1.1.1.1") /
    TCP(sport=51543, dport=443, flags="S"),

    IP(src="192.168.1.20", dst="8.8.8.8") /
    UDP(sport=53001, dport=53) /
    DNS(rd=1, qd=DNSQR(qname="test.example"))
]

wrpcap("training.pcap", packets)

print("Created training.pcap")
print("Total packets:", len(packets))
