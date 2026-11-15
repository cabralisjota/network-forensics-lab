from scapy.all import PcapReader, IP, TCP
from collections import defaultdict
from datetime import datetime, timezone
import json

WINDOW = 60
THRESHOLD = 5

traffic = defaultdict(list)

with PcapReader("timed_traffic.pcap") as capture:
    for pkt in capture:
        if IP not in pkt or TCP not in pkt:
            continue

        tcp = pkt[TCP]

        # Count initial SYN packets, not SYN-ACK replies
        if not (int(tcp.flags) & 0x02) or (int(tcp.flags) & 0x10):
            continue

        key = (pkt[IP].src, pkt[IP].dst)
        traffic[key].append((float(pkt.time), int(tcp.dport)))

alerts = []

for (source, target), events in traffic.items():
    events.sort()

    for i, (start, _) in enumerate(events):
        ports = {
            port for timestamp, port in events[i:]
            if timestamp - start <= WINDOW
        }

        if len(ports) >= THRESHOLD:
            alert = {
                "type": "POSSIBLE_PORT_SCAN",
                "severity": "MEDIUM",
                "source_ip": source,
                "target_ip": target,
                "unique_ports": len(ports),
                "ports": sorted(ports),
                "window_seconds": WINDOW,
                "first_seen": datetime.fromtimestamp(
                    start, timezone.utc
                ).isoformat()
            }

            alerts.append(alert)
            break

print("\n=== NETWORK DETECTION REPORT ===")
print("Source-target pairs analyzed:", len(traffic))
print("Alerts generated:", len(alerts))

for alert in alerts:
    print("\n[ALERT] Possible rapid port scan")
    print("Source:", alert["source_ip"])
    print("Target:", alert["target_ip"])
    print("Ports:", alert["ports"])
    print("Unique ports:", alert["unique_ports"])
    print("First seen:", alert["first_seen"])

with open("alerts.json", "w") as f:
    json.dump(alerts, f, indent=4)

print("\nReport saved to alerts.json")
