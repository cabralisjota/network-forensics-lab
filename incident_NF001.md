# Incident NF-001: Possible TCP Port Scan

## Investigation Type
Simulated Network Forensics Exercise

## Severity
Medium (Training Classification)

## Executive Summary
A simulated source host, 192.168.1.50, sent
10 TCP SYN packets to 10 different ports on
192.168.1.100 over approximately 9 seconds.

The pattern is consistent with possible
network reconnaissance.

## Evidence
- Source IP: 192.168.1.50
- Destination IP: 192.168.1.100
- Protocol: TCP
- TCP flag: SYN
- Unique destination ports: 10
- Observation duration: 9 seconds
- Source file: timed_traffic.pcap

## Findings
The source rapidly probed multiple services.

No server responses were included in the
training capture.

There is insufficient evidence to determine
whether any connection succeeded or whether
the destination host was compromised.

## Recommendations
1. Verify whether scanning was authorized.
2. Review firewall logs.
3. Investigate destination service logs.
4. Check for subsequent successful connections.
5. Escalate if malicious activity is confirmed.

## Conclusion
Possible reconnaissance activity detected.

This exercise uses synthetic network traffic
and does not represent a real security incident.
