from scapy.all import IP, TCP, wrpcap

packets = []

source = "192.168.1.50"
target = "192.168.1.100"

ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389]

for port in ports:
    packet = (
        IP(src=source, dst=target) /
        TCP(sport=50000, dport=port, flags="S")
    )
    packets.append(packet)

wrpcap("port_scan.pcap", packets)

print("Training PCAP created.")
print("Packets:", len(packets))
print("Target:", target)
print("Ports tested:", ports)
