import tempfile
from pathlib import Path
from scapy.all import IP, TCP, wrpcap
from ids_engine import analyze

BASE = 1700000000.0

def packet(src, dst, port, flags, offset, sport=40000):
    p = IP(src=src, dst=dst) / TCP(
        sport=sport,
        dport=port,
        flags=flags
    )
    p.time = BASE + offset
    return p

def run_test(name, packets, expected, folder):
    path = folder / (name + ".pcap")
    wrpcap(str(path), packets)

    result = analyze(path)
    actual = {a["rule"] for a in result["alerts"]}

    passed = actual == expected
    status = "PASS" if passed else "FAIL"

    print(f"[{status}] {name}")
    if not passed:
        print(" Expected:", sorted(expected))
        print(" Actual:", sorted(actual))

    return passed

def main():
    tests = []

    scan = [
        packet("192.0.2.1", "192.0.2.2",
               port, "S", i, 40000 + i)
        for i, port in enumerate([21,22,23,25,80])
    ]
    tests.append((
        "port_scan", scan, {"TCP_PORT_SCAN"}
    ))

    normal = [
        packet("192.0.2.3", "192.0.2.4",
               80, "S", 0),
        packet("192.0.2.4", "192.0.2.3",
               40000, "SA", 0.1, 80),
        packet("192.0.2.3", "192.0.2.4",
               80, "A", 0.2)
    ]
    tests.append(("normal", normal, set()))

    tests.append((
        "null_scan",
        [packet("192.0.2.5","192.0.2.6",
                80, 0, 0)],
        {"TCP_NULL_SCAN"}
    ))

    tests.append((
        "fin_scan",
        [packet("192.0.2.7","192.0.2.8",
                80, "F", 0)],
        {"TCP_FIN_SCAN"}
    ))

    tests.append((
        "xmas_scan",
        [packet("192.0.2.9","192.0.2.10",
                80, "FPU", 0)],
        {"TCP_XMAS_SCAN"}
    ))

    burst = [
        packet("192.0.2.11","192.0.2.12",
               443, "S", i * 0.1, 41000 + i)
        for i in range(110)
    ]
    tests.append((
        "syn_burst", burst, {"TCP_SYN_BURST"}
    ))

    # Packets intentionally out of timestamp order
    unordered = list(reversed(scan))
    tests.append((
        "unordered_packets",
        unordered, {"TCP_PORT_SCAN"}
    ))

    passed = 0

    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)

        for name, packets, expected in tests:
            if run_test(name, packets, expected, folder):
                passed += 1

    print(f"\nTests passed: {passed}/{len(tests)}")
    return passed == len(tests)

if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
