from scapy.all import PcapReader, IP, TCP, UDP, Raw
from collections import Counter
from datetime import datetime, timezone
import json
import sys

filename = sys.argv[1] if len(sys.argv) > 1 else "http.cap"

report = {
    "capture_file": filename,
    "total_packets": 0,
    "protocols": Counter(),
    "source_ips": Counter(),
    "tcp_conversations": Counter(),
    "http_messages": []
}

with PcapReader(filename) as capture:
    for number, pkt in enumerate(capture, 1):
        report["total_packets"] += 1

        if IP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        report["source_ips"][src] += 1

        if TCP in pkt:
            report["protocols"]["TCP"] += 1

            tcp = pkt[TCP]
            endpoints = sorted([
                f"{src}:{tcp.sport}",
                f"{dst}:{tcp.dport}"
            ])
            conversation = " <-> ".join(endpoints)
            report["tcp_conversations"][conversation] += 1

            if Raw in pkt:
                data = bytes(pkt[Raw].load)
                first = data.split(b"\r\n", 1)[0]

                if first.startswith((
                    b"GET ", b"POST ", b"HEAD ",
                    b"PUT ", b"DELETE ", b"HTTP/"
                )):
                    report["http_messages"].append({
                        "packet": number,
                        "source": src,
                        "destination": dst,
                        "message": first.decode(
                            "utf-8", errors="replace"
                        )
                    })

        elif UDP in pkt:
            report["protocols"]["UDP"] += 1

        else:
            report["protocols"]["OTHER_IP"] += 1

report["protocols"] = dict(report["protocols"])
report["source_ips"] = dict(report["source_ips"])
report["tcp_conversations"] = dict(report["tcp_conversations"])

report["generated_at"] = datetime.now(
    timezone.utc
).isoformat()

with open("forensic_report.json", "w") as output:
    json.dump(report, output, indent=4)

print("\n=== AUTOMATED FORENSIC REPORT ===")
print("Capture:", filename)
print("Packets:", report["total_packets"])
print("Protocols:", report["protocols"])
print("TCP conversations:", len(report["tcp_conversations"]))
print("HTTP messages:", len(report["http_messages"]))
print("\nSaved: forensic_report.json")
