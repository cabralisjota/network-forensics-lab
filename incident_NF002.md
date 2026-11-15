# Network Forensics Investigation NF-002

## Case Type
HTTP Traffic Analysis — Real Recorded PCAP

## Evidence Source
Wireshark Sample Capture: http.cap

## Executive Summary
Analyzed a recorded HTTP packet capture using
Python and Scapy in Android Termux.

The capture contained 43 packets, including
41 TCP packets across two TCP conversations.

## Network Evidence

### Conversation 1 — Website
Client: 145.254.160.237:3372
Server: 65.208.228.223:80
Packets: 34

HTTP Request:
GET /download.html HTTP/1.1

Host: www.ethereal.com
Response: HTTP/1.1 200 OK

### Conversation 2 — Advertising
Client: 145.254.160.237:3371
Server: 216.239.59.99:80
Packets: 7

HTTP Request:
GET /pagead/ads?... HTTP/1.1

Host: pagead2.googlesyndication.com
Observed responses: HTTP/1.1 200 OK

## Findings
1. The client communicated with two servers.
2. The primary request targeted a download webpage.
3. A separate request targeted an advertising service.
4. The advertising request referenced the original page.
5. The observed HTTP responses reported success.

## Security Assessment
The observed activity is consistent with
ordinary HTTP browsing and third-party content
loading.

No malicious activity or system compromise
was established by the examined evidence.

## Limitations
The analysis used basic packet-level extraction,
not full TCP stream reassembly.

Only traffic present in the capture was assessed.

## Conclusion
The investigation reconstructed two TCP
conversations and identified HTTP application
activity using Python and Scapy.
