from scapy.all import PcapReader, IP, TCP, Raw
from collections import defaultdict

streams = defaultdict(list)

with PcapReader("http.cap") as capture:
    for packet in capture:
        if IP not in packet or TCP not in packet:
            continue

        if Raw not in packet:
            continue

        ip = packet[IP]
        tcp = packet[TCP]

        key = (
            ip.src,
            tcp.sport,
            ip.dst,
            tcp.dport
        )

        streams[key].append({
            "seq": int(tcp.seq),
            "data": bytes(packet[Raw].load)
        })

print("\n=== TCP STREAM REASSEMBLY ===")

for key, segments in streams.items():

    source, sport, target, dport = key

    # Sort segments by TCP sequence number
    segments.sort(key=lambda x: x["seq"])

    # Build a contiguous stream from observed data
    reconstructed = bytearray()
    next_seq = None
    gaps = []

    for segment in segments:
        seq = segment["seq"]
        data = segment["data"]

        if next_seq is None:
            next_seq = seq

        if seq > next_seq:
            gaps.append((next_seq, seq))
            next_seq = seq

        # Skip already reconstructed bytes
        overlap = max(0, next_seq - seq)

        if overlap >= len(data):
            continue

        new_data = data[overlap:]
        reconstructed.extend(new_data)
        next_seq = seq + len(data)

    print("\n---------------------------")
    print(f"{source}:{sport}")
    print("        ->")
    print(f"{target}:{dport}")
    print("Segments:", len(segments))
    print("Reconstructed bytes:", len(reconstructed))

    if gaps:
        print("WARNING: Missing sequence ranges:", gaps)

    preview = reconstructed[:300].decode(
        "utf-8", errors="replace"
    )

    print("\nDATA PREVIEW:")
    print(preview)

print("\nAnalysis complete.")
