#!/usr/bin/env python3
"""Check attestation of a Secret VM."""

import json
import sys
from dataclasses import asdict
from secretvm.verify import check_secret_vm


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url> [--product NAME] [--raw] [--verbose|-v] [--reload-amd-kds]")
        print(f"  e.g. {sys.argv[0]} https://my-vm:29343")
        print(f"  Default output is the verdict only; use --verbose for the per-check")
        print(f"  breakdown and report field details.")
        print(f"  --reload-amd-kds bypasses the local AMD KDS cache and re-fetches")
        print(f"  VCEK, CA cert chain, and CRL from kdsintf.amd.com (no effect on TDX).")
        sys.exit(1)

    url = sys.argv[1]
    product = ""
    if "--product" in sys.argv:
        idx = sys.argv.index("--product")
        if idx + 1 < len(sys.argv):
            product = sys.argv[idx + 1]

    raw = "--raw" in sys.argv
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    reload_amd_kds = "--reload-amd-kds" in sys.argv

    if not raw:
        print(f"Verifying {url}\n")
    result = check_secret_vm(url, product=product, reload_amd_kds=reload_amd_kds)

    if raw:
        print(json.dumps(asdict(result), indent=2))
        sys.exit(0 if result.valid else 1)

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
        report = result.report
        cpu_quote = report.get("cpu")
        if cpu_quote is None and result.attestation_type in ("TDX", "SEV-SNP"):
            cpu_quote = report
        gpu_quote = report.get("gpu")
        if gpu_quote is None and result.attestation_type == "NVIDIA-GPU":
            gpu_quote = report
        if cpu_quote:
            print("\nCPU quote:")
            print(json.dumps(cpu_quote, indent=2, default=str))
        if gpu_quote:
            print("\nGPU quote:")
            print(json.dumps(gpu_quote, indent=2, default=str))
        poc = report.get("proof_of_cloud")
        if poc:
            print("\nProof of cloud:")
            print(json.dumps(poc, indent=2, default=str))

    # Errors
    if result.errors:
        print(f"\nErrors:")
        for err in result.errors:
            print(f"  - {err}")

    # Verdict
    print(f"\n{'✅ All Passed' if result.valid else '🚫 Failed'}")
    sys.exit(0 if result.valid else 1)


if __name__ == "__main__":
    main()
