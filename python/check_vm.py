#!/usr/bin/env python3
"""Check attestation of a Secret VM."""

import json
import sys
from dataclasses import asdict
from secretvm.verify import check_secret_vm


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url> [--product NAME] [--raw] [--verbose|-v]")
        print(f"  e.g. {sys.argv[0]} https://my-vm:29343")
        print(f"  Default output is the verdict only; use --verbose for the per-check")
        print(f"  breakdown and report field details.")
        sys.exit(1)

    url = sys.argv[1]
    product = ""
    if "--product" in sys.argv:
        idx = sys.argv.index("--product")
        if idx + 1 < len(sys.argv):
            product = sys.argv[idx + 1]

    raw = "--raw" in sys.argv
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    if not raw:
        print(f"Checking attestation for {url} ...\n")
    result = check_secret_vm(url, product=product)

    if raw:
        print(json.dumps(asdict(result), indent=2))
        sys.exit(0 if result.valid else 1)

    # Prominent top-level cryptographic attestation verdict.
    # Prefer the dcap-qvl `quote_verified` signal (direct CPU/TDX call), or
    # its propagated form `cpu_quote_verified` from a wrapper (check_secret_vm,
    # verify_agent). Fall back to other CPU verdict signals so this line works
    # across all attestation types.
    c = result.checks
    verdict = None
    for key in ("quote_verified", "cpu_quote_verified",
                "report_signature_valid", "cpu_attestation_valid"):
        if key in c:
            verdict = bool(c[key])
            break
    if verdict is not None:
        label = "PASS" if verdict else "FAIL"
        icon = "✅" if verdict else "🚫"
        print(f"{icon} Attestation verified: {label}\n")

    # The per-check PASS/FAIL breakdown is always shown. The report-field
    # highlights (CPU/TLS/RTMR/TCB/GPU/workload specifics) are gated behind
    # --verbose to keep the default output focused on the verdict.
    print("Checks:")
    for name, passed in result.checks.items():
        if name == "gpu_quote_fetched" and not passed:
            print(f"  {'gpu:':<35} GPU not present")
            continue
        status = "PASS" if passed else "FAIL"
        print(f"  {name + ':':<35} {status}")

    if verbose:
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
            print(f"MR TD:  {cpu['mr_td']}")
        if cpu.get("rt_mr0"):
            print(f"RTMR0:  {cpu['rt_mr0']}")
        if cpu.get("rt_mr1"):
            print(f"RTMR1:  {cpu['rt_mr1']}")
        if cpu.get("rt_mr2"):
            print(f"RTMR2:  {cpu['rt_mr2']}")
        if cpu.get("rt_mr3"):
            print(f"RTMR3:  {cpu['rt_mr3']}")
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

        workload = report.get("workload", {})
        if workload:
            print(f"\nWorkload status: {workload.get('status')}")
            if workload.get("template_name"):
                print(f"Template: {workload['template_name']}")
            if workload.get("artifacts_ver"):
                print(f"Version: {workload['artifacts_ver']}")
            if workload.get("env"):
                print(f"Environment: {workload['env']}")

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
