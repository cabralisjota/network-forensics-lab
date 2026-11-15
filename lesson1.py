from scapy.all import IP, TCP, UDP, DNS, DNSQR

packets = [
    IP(src="192.168.1.10", dst="8.8.8.8") /
    UDP(sport=53000, dport=53) /
    DNS(rd=1, qd=DNSQR(qname="example.com")),

    IP(src="192.168.1.10", dst="93.184.215.14") /
    TCP(sport=51542, dport=80, flags="S"),

    IP(src="192.168.1.10", dst="1.1.1.1") /
    TCP(sport=51543, dport=443, flags="S"),
]

for number, packet in enumerate(packets, 1):
    print(f"\n--- Packet {number} ---")
    print("Source IP:", packet[IP].src)
    print("Destination IP:", packet[IP].dst)

    if packet.haslayer(TCP):
        print("Protocol: TCP")
        print("Destination port:", packet[TCP].dport)
        print("TCP flags:", packet[TCP].flags)

    elif packet.haslayer(UDP):
        print("Protocol: UDP")
        print("Destination port:", packet[UDP].dport)

    if packet.haslayer(DNSQR):
        print("DNS query:", packet[DNSQR].qname.decode())
