from scapy.all import PcapReader, IP, TCP
from collections import Counter

conversations = Counter()

with PcapReader("http.cap") as capture:
    for pkt in capture:
        if IP not in pkt or TCP not in pkt:
            continue

        src = (pkt[IP].src, int(pkt[TCP].sport))
        dst = (pkt[IP].dst, int(pkt[TCP].dport))

        # Combine both directions into one conversation
        pair = tuple(sorted([src, dst]))
        conversations[pair] += 1

print("\n=== TCP NETWORK CONVERSATIONS ===")

for number, (pair, count) in enumerate(
    conversations.most_common(), 1
):
    endpoint1, endpoint2 = pair

    print(f"\nConversation #{number}")
    print(f"{endpoint1[0]}:{endpoint1[1]}")
    print("        <-->")
    print(f"{endpoint2[0]}:{endpoint2[1]}")
    print("Packets:", count)

print("\nTotal TCP conversations:", len(conversations))
