from scapy.all import PcapReader, IP, TCP
from collections import defaultdict, deque
import json
import sys

PCAP = sys.argv[1] if len(sys.argv) > 1 else "timed_traffic.pcap"

WINDOW = 60
PORT_THRESHOLD = 5
SYN_THRESHOLD = 100

port_history = defaultdict(deque)
syn_history = defaultdict(deque)

alerts = []
reported = set()

def create_alert(rule, severity, src, dst, details, timestamp):
    alert = {
        "rule": rule,
        "severity": severity,
        "source_ip": src,
        "destination_ip": dst,
        "timestamp": timestamp,
        "details": details
    }

    alerts.append(alert)

    print(f"\n[{severity}] {rule}")
    print(f"Source: {src}")
    print(f"Target: {dst}")
    print(f"Details: {details}")


with PcapReader(PCAP) as capture:
    for packet in capture:

        if IP not in packet or TCP not in packet:
            continue

        ip = packet[IP]
        tcp = packet[TCP]

        src = ip.src
        dst = ip.dst
        flags = int(tcp.flags)
        timestamp = float(packet.time)

        key = (src, dst)

        # Rule 1: TCP NULL scan pattern
        if flags == 0:
            alert_key = ("TCP_NULL_SCAN", key)

            if alert_key not in reported:
                create_alert(
                    "TCP_NULL_SCAN",
                    "MEDIUM",
                    src, dst,
                    {"flags": 0, "destination_port": int(tcp.dport)},
                    timestamp
                )
                reported.add(alert_key)

        # Count initial SYN packets only
        if not (flags & 0x02) or (flags & 0x10):
            continue

        port_history[key].append(
            (timestamp, int(tcp.dport))
        )
        syn_history[key].append(timestamp)

        # Remove old observations
        while port_history[key] and (
            timestamp - port_history[key][0][0] > WINDOW
        ):
            port_history[key].popleft()

        while syn_history[key] and (
            timestamp - syn_history[key][0] > WINDOW
        ):
            syn_history[key].popleft()

        # Rule 2: Port scan
        unique_ports = {
            port for _, port in port_history[key]
        }

        alert_key = ("TCP_PORT_SCAN", key)

        if (
            len(unique_ports) >= PORT_THRESHOLD
            and alert_key not in reported
        ):
            create_alert(
                "TCP_PORT_SCAN",
                "MEDIUM",
                src, dst,
                {
                    "unique_ports": len(unique_ports),
                    "ports": sorted(unique_ports),
                    "window_seconds": WINDOW
                },
                timestamp
            )
            reported.add(alert_key)

        # Rule 3: SYN burst
        alert_key = ("TCP_SYN_BURST", key)

        if (
            len(syn_history[key]) >= SYN_THRESHOLD
            and alert_key not in reported
        ):
            create_alert(
                "TCP_SYN_BURST",
                "HIGH",
                src, dst,
                {
                    "syn_count": len(syn_history[key]),
                    "window_seconds": WINDOW
                },
                timestamp
            )
            reported.add(alert_key)


with open("ids_alerts.json", "w") as output:
    json.dump(alerts, output, indent=4)

print("\n=== IDS SUMMARY ===")
print("Capture:", PCAP)
print("Alerts generated:", len(alerts))
print("Saved: ids_alerts.json")
