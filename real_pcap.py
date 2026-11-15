from scapy.all import PcapReader, IP, TCP, Raw

filename = "http.cap"

print("\n=== HTTP NETWORK INVESTIGATION ===")

total = 0
tcp_count = 0
http_count = 0

with PcapReader(filename) as capture:
    for packet in capture:
        total += 1

        if IP not in packet or TCP not in packet:
            continue

        tcp_count += 1

        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = str(packet[TCP].flags)

        print(f"\nPacket #{total}")
        print(f"{src}:{sport} -> {dst}:{dport}")
        print("TCP flags:", flags)

        if Raw in packet:
            data = bytes(packet[Raw].load)

            if data.startswith((
                b"GET ", b"POST ", b"HEAD ",
                b"PUT ", b"DELETE ", b"HTTP/"
            )):
                http_count += 1

                first_line = data.split(b"\r\n")[0]

                print(
                    "HTTP:",
                    first_line.decode(
                        "utf-8", errors="replace"
                    )
                )

print("\n=== SUMMARY ===")
print("Total packets:", total)
print("TCP packets:", tcp_count)
print("HTTP messages found:", http_count)
