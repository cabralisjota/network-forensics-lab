# Network Forensics Lab

A Python-based network forensics toolkit developed
using Android Termux and Scapy.

## Features

- PCAP file analysis
- TCP and UDP packet inspection
- TCP conversation identification
- HTTP request and response extraction
- Basic TCP stream reassembly
- Time-based port scan detection
- JSON forensic report generation
- Incident investigation documentation

## Technologies

- Python
- Scapy
- TCP/IP
- HTTP
- JSON
- Android Termux

## Usage

Install dependencies:

pip install -r requirements.txt

Analyze an HTTP capture:

python forensic_report.py http.cap

Detect simulated port scanning:

python timed_detector.py

Extract HTTP messages:

python extract_http.py

## Investigations

### NF-001: Possible TCP Port Scan

Simulated network reconnaissance involving
10 destination ports probed within 9 seconds.

### NF-002: HTTP Traffic Investigation

Analysis of a recorded Wireshark sample capture.

Findings:
- 43 packets
- 41 TCP packets
- 2 TCP conversations
- 5 detected HTTP message starts

## Limitations

- Port scan detection uses a basic threshold.
- TCP reassembly is educational, not production-grade.
- HTTP extraction does not fully reassemble streams.
- Training captures do not demonstrate real compromise.

## Ethical Use

This project is intended for cybersecurity education,
authorized network analysis, and incident response training.
