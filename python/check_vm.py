#!/usr/bin/env python3
"""Check attestation of a Secret VM."""

import json
import sys
from dataclasses import asdict
from secretvm.verify import check_secret_vm


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url> [--product NAME]")
        print(f"  e.g. {sys.argv[0]} https://my-vm:29343")
        sys.exit(1)

    url = sys.argv[1]
    product = ""
    if "--product" in sys.argv:
        idx = sys.argv.index("--product")
        if idx + 1 < len(sys.argv):
            product = sys.argv[idx + 1]

    raw = "--raw" in sys.argv

    if not raw:
        print(f"Checking attestation for {url} ...\n")
    result = check_secret_vm(url, product=product)

    if raw:
        print(json.dumps(asdict(result), indent=2))
        sys.exit(0 if result.valid else 1)

    # Checks
    print("Checks:")
    for name, passed in result.checks.items():
        if name == "gpu_quote_fetched" and not passed:
            print(f"  {'gpu:':<35} GPU not present")
            continue
        status = "PASS" if passed else "FAIL"
        print(f"  {name + ':':<35} {status}")

    # Report highlights
    report = result.report
    if report.get("cpu_type"):
        print(f"\nCPU type: {report['cpu_type']}")
    if report.get("tls_fingerprint"):
        print(f"TLS fingerprint: {report['tls_fingerprint']}")

    cpu = report.get("cpu", {})
    if cpu.get("report_data"):
        print(f"Report data: {cpu['report_data']}")
    if cpu.get("measurement"):
        print(f"Measurement: {cpu['measurement']}")
    if cpu.get("mr_td"):
        print(f"MR TD: {cpu['mr_td']}")
    if cpu.get("tcb_status"):
        print(f"TCB status: {cpu['tcb_status']}")
    if cpu.get("product"):
        print(f"AMD product: {cpu['product']}")

    gpu = report.get("gpu", {})
    if gpu.get("gpus"):
        for gpu_id, info in gpu["gpus"].items():
            print(f"\n{gpu_id}:")
            print(f"  Model: {info.get('model')}")
            print(f"  Driver: {info.get('driver_version')}")
            print(f"  Secure boot: {info.get('secure_boot')}")

    # Errors
    if result.errors:
        print(f"\nErrors:")
        for err in result.errors:
            print(f"  - {err}")

    # Verdict
    print(f"\n{'PASSED' if result.valid else 'FAILED'}")
    sys.exit(0 if result.valid else 1)


if __name__ == "__main__":
    main()
