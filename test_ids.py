import json
import subprocess
import sys

TESTS = [
    {
        "pcap": "timed_traffic.pcap",
        "expected": {"TCP_PORT_SCAN"}
    },
    {
        "pcap": "http.cap",
        "expected": set()
    },
    {
        "pcap": "ids_test.pcap",
        "expected": {
            "TCP_NULL_SCAN",
            "TCP_SYN_BURST"
        }
    }
]

passed = 0

print("\n=== IDS AUTOMATED TEST SUITE ===")

for test in TESTS:
    pcap = test["pcap"]

    result = subprocess.run(
        [sys.executable, "ids_engine.py", pcap],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"\n[FAIL] {pcap}")
        print(result.stderr)
        continue

    try:
        with open("ids_alerts.json") as f:
            alerts = json.load(f)

        actual = {alert["rule"] for alert in alerts}
        expected = test["expected"]

        if actual == expected and len(alerts) == len(expected):
            print(f"[PASS] {pcap}: {sorted(actual)}")
            passed += 1
        else:
            print(f"[FAIL] {pcap}")
            print("Expected:", sorted(expected))
            print("Actual:", sorted(actual))
            print("Alert count:", len(alerts))

    except (OSError, ValueError, KeyError) as error:
        print(f"[FAIL] {pcap}: {error}")

print("\n=== TEST SUMMARY ===")
print(f"Passed: {passed}/{len(TESTS)}")

if passed != len(TESTS):
    sys.exit(1)
