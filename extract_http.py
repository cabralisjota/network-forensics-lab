from scapy.all import PcapReader, IP, TCP, Raw

print("\n=== HTTP FORENSICS REPORT ===")

count = 0

with PcapReader("http.cap") as capture:
    for number, pkt in enumerate(capture, 1):

        if IP not in pkt or TCP not in pkt:
            continue

        if Raw not in pkt:
            continue

        data = bytes(pkt[Raw].load)

        methods = (
            b"GET ", b"POST ", b"HEAD ",
            b"PUT ", b"DELETE ", b"HTTP/"
        )

        if not data.startswith(methods):
            continue

        count += 1

        source = pkt[IP].src
        target = pkt[IP].dst

        first_line = data.split(b"\r\n")[0]

        print(f"\nHTTP Message #{count}")
        print("Packet:", number)
        print("Source:", source)
        print("Destination:", target)
        print("Message:", first_line.decode(
            "utf-8", errors="replace"
        ))

        for line in data.split(b"\r\n")[1:]:
            if line.lower().startswith(b"host:"):
                print("Host:", line.decode(
                    "utf-8", errors="replace"
                ))

print("\nTotal HTTP messages:", count)
