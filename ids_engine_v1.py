from scapy.all import PcapReader, IP, TCP
from collections import defaultdict, deque
import json
import sys

PCAP = sys.argv[1] if len(sys.argv) > 1 else "timed_traffic.pcap"

WINDOW = 60
PORT_THRESHOLD = 5

history = defaultdict(deque)
alerts = []
alerted = set()

with PcapReader(PCAP) as capture:
    for packet in capture:

        if IP not in packet or TCP not in packet:
            continue

        ip = packet[IP]
        tcp = packet[TCP]

        # Only count initial SYN packets
        flags = int(tcp.flags)

        if not (flags & 0x02) or (flags & 0x10):
            continue

        timestamp = float(packet.time)
        key = (ip.src, ip.dst)

        history[key].append((timestamp, int(tcp.dport)))

        # Remove packets outside the time window
        while history[key] and (
            timestamp - history[key][0][0] > WINDOW
        ):
            history[key].popleft()

        unique_ports = {
            port for _, port in history[key]
        }

        if len(unique_ports) >= PORT_THRESHOLD:
            if key not in alerted:
                alert = {
                    "rule": "TCP_PORT_SCAN",
                    "severity": "MEDIUM",
                    "source_ip": ip.src,
                    "destination_ip": ip.dst,
                    "unique_ports": len(unique_ports),
                    "ports": sorted(unique_ports),
                    "window_seconds": WINDOW,
                    "timestamp": timestamp
                }

                alerts.append(alert)
                alerted.add(key)

                print("\n[ALERT] Potential TCP port scan")
                print("Source:", ip.src)
                print("Target:", ip.dst)
                print("Unique ports:", len(unique_ports))

with open("ids_alerts.json", "w") as output:
    json.dump(alerts, output, indent=4)

print("\n=== IDS SUMMARY ===")
print("Capture:", PCAP)
print("Alerts generated:", len(alerts))
print("Saved: ids_alerts.json")
