from scapy.all import PcapReader, IP, TCP
from datetime import datetime, timezone

print("\n=== INCIDENT NF-001 ===")
print("TCP SYN Investigation\n")

events = []

with PcapReader("timed_traffic.pcap") as pcap:
    for packet in pcap:
        if IP not in packet or TCP not in packet:
            continue

        tcp = packet[TCP]

        # Initial SYN, excluding SYN-ACK
        if int(tcp.flags) & 0x12 != 0x02:
            continue

        if packet[IP].src != "192.168.1.50":
            continue

        timestamp = float(packet.time)

        events.append({
            "time": timestamp,
            "source": packet[IP].src,
            "target": packet[IP].dst,
            "port": int(tcp.dport)
        })

events.sort(key=lambda x: x["time"])

for event in events:
    readable = datetime.fromtimestamp(
        event["time"], timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    print(
        f"{readable} | "
        f"{event['source']} -> "
        f"{event['target']} | "
        f"Port {event['port']}"
    )

if events:
    duration = events[-1]["time"] - events[0]["time"]

    print("\n=== FINDINGS ===")
    print("Packets:", len(events))
    print("Duration:", duration, "seconds")
    print("Unique ports:", len(set(e["port"] for e in events)))
    print("Assessment: Possible rapid TCP port scan")
else:
    print("No matching SYN packets found.")
