from scapy.all import PcapReader, IP, TCP
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
import argparse
import json

WINDOW = 60
PORT_THRESHOLD = 5
SYN_THRESHOLD = 100

def iso_time(timestamp):
    return datetime.fromtimestamp(
        timestamp, timezone.utc
    ).isoformat()

def analyze(pcap):
    packets = []

    with PcapReader(str(pcap)) as capture:
        for number, pkt in enumerate(capture, 1):
            if IP not in pkt or TCP not in pkt:
                continue

            tcp = pkt[TCP]

            packets.append({
                "number": number,
                "time": float(pkt.time),
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "sport": int(tcp.sport),
                "dport": int(tcp.dport),
                "flags": int(tcp.flags)
            })

    # Sort by capture timestamp
    packets.sort(key=lambda p: (p["time"], p["number"]))

    port_history = defaultdict(deque)
    syn_history = defaultdict(deque)

    alerts = []
    reported = set()

    def add_alert(rule, severity, pkt, evidence):
        key = (rule, pkt["src"], pkt["dst"])

        if key in reported:
            return

        reported.add(key)

        alerts.append({
            "rule": rule,
            "severity": severity,
            "source_ip": pkt["src"],
            "destination_ip": pkt["dst"],
            "timestamp": iso_time(pkt["time"]),
            "packet_number": pkt["number"],
            "evidence": evidence
        })

    for pkt in packets:
        src = pkt["src"]
        dst = pkt["dst"]
        flags = pkt["flags"]
        timestamp = pkt["time"]
        key = (src, dst)

        # TCP NULL pattern
        if flags == 0:
            add_alert(
                "TCP_NULL_SCAN", "MEDIUM", pkt,
                {"destination_port": pkt["dport"]}
            )

        # TCP FIN-only pattern
        if flags == 0x01:
            add_alert(
                "TCP_FIN_SCAN", "MEDIUM", pkt,
                {"destination_port": pkt["dport"]}
            )

        # TCP Xmas pattern: FIN + PSH + URG
        if flags == 0x29:
            add_alert(
                "TCP_XMAS_SCAN", "MEDIUM", pkt,
                {"destination_port": pkt["dport"]}
            )

        # Initial SYN, excluding SYN-ACK
        if not (flags & 0x02) or (flags & 0x10):
            continue

        port_history[key].append(
            (timestamp, pkt["dport"])
        )
        syn_history[key].append(timestamp)

        while port_history[key] and (
            timestamp - port_history[key][0][0] > WINDOW
        ):
            port_history[key].popleft()

        while syn_history[key] and (
            timestamp - syn_history[key][0] > WINDOW
        ):
            syn_history[key].popleft()

        ports = sorted({
            port for _, port in port_history[key]
        })

        if len(ports) >= PORT_THRESHOLD:
            add_alert(
                "TCP_PORT_SCAN", "MEDIUM", pkt,
                {
                    "unique_ports": len(ports),
                    "ports": ports,
                    "window_seconds": WINDOW
                }
            )

        if len(syn_history[key]) >= SYN_THRESHOLD:
            add_alert(
                "TCP_SYN_BURST", "HIGH", pkt,
                {
                    "syn_count": len(syn_history[key]),
                    "window_seconds": WINDOW
                }
            )

    return {
        "engine": "Network Forensics IDS v2.0",
        "capture": str(pcap),
        "tcp_packets_analyzed": len(packets),
        "alerts_count": len(alerts),
        "alerts": alerts
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Input PCAP file")
    parser.add_argument(
        "--output", default="ids_alerts.json"
    )
    args = parser.parse_args()

    result = analyze(args.pcap)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print("\n=== NETWORK FORENSICS IDS v2.0 ===")
    print("Capture:", result["capture"])
    print("TCP packets:", result["tcp_packets_analyzed"])

    for alert in result["alerts"]:
        print(
            f"[{alert['severity']}] {alert['rule']}"
            f" | {alert['source_ip']}"
            f" -> {alert['destination_ip']}"
        )

    print("Total alerts:", result["alerts_count"])
    print("Saved:", args.output)


if __name__ == "__main__":
    main()
