import argparse
import json
from datetime import datetime, timezone

parser = argparse.ArgumentParser()
parser.add_argument(
    "input", nargs="?", default="ids_alerts.json"
)
parser.add_argument(
    "--output", default="ids_incident_report.md"
)
args = parser.parse_args()

with open(args.input) as f:
    data = json.load(f)

lines = [
    "# Network IDS Investigation Report",
    "",
    "## Summary",
    "",
    f"- Engine: {data['engine']}",
    f"- Capture: {data['capture']}",
    f"- TCP packets: {data['tcp_packets_analyzed']}",
    f"- Alerts: {data['alerts_count']}",
    f"- Generated: {datetime.now(timezone.utc).isoformat()}",
    "",
    "## Findings",
    ""
]

if not data["alerts"]:
    lines.append("No detection rules were triggered.")
else:
    for i, alert in enumerate(data["alerts"], 1):
        lines.extend([
            f"### Finding {i}: {alert['rule']}",
            "",
            f"- Severity: {alert['severity']}",
            f"- Source: {alert['source_ip']}",
            f"- Destination: {alert['destination_ip']}",
            f"- Time (UTC): {alert['timestamp']}",
            f"- Packet number: {alert['packet_number']}",
            "",
            "**Evidence:**",
            "",
            "```json",
            json.dumps(alert["evidence"], indent=2),
            "```",
            ""
        ])

lines.extend([
    "## Assessment",
    "",
    "These findings represent rule-based indicators.",
    "They do not independently establish malicious intent.",
    "",
    "## Limitations",
    "",
    "- Offline packet analysis only",
    "- Experimental detection thresholds",
    "- Possible false positives and false negatives",
    "- No TCP session-state reconstruction",
    "- One alert per rule and endpoint pair",
    "- SYN retransmissions are not distinguished",
    "",
    "## Recommended Follow-up",
    "",
    "Correlate alerts with additional network evidence,",
    "host logs, and authorized investigation records."
])

with open(args.output, "w") as f:
    f.write("\n".join(lines) + "\n")

print("Report saved:", args.output)
