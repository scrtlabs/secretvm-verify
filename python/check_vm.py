#!/usr/bin/env python3
"""Check attestation of a Secret VM."""

import json
import sys
from dataclasses import asdict
from secretvm.verify import check_secret_vm


def _get_opt(name: str):
    if name in sys.argv:
        idx = sys.argv.index(name)
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    return None


def main():
    if "--version" in sys.argv or "-V" in sys.argv:
        from importlib.metadata import PackageNotFoundError, version as _version
        try:
            print(f"secretvm-verify {_version('secretvm-verify')}")
        except PackageNotFoundError:
            print("secretvm-verify (unknown — not installed via pip)")
        sys.exit(0)

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url> [--product NAME] [--json|--raw] [--verbose|-v] [--reload-amd-kds] [--strict] [--proof-of-cloud] [--show-compose] [--docker-files <tar> | --docker-files-sha256 <hex>] [--version|-V]")
        print(f"  e.g. {sys.argv[0]} https://my-vm:29343")
        print(f"  Default output is the per-check PASS/FAIL breakdown. Use --json for")
        print(f"  minimal JSON (no report fields), --raw for full JSON, or --verbose for")
        print(f"  the text breakdown with parsed CPU/GPU/proof-of-cloud quotes.")
        print(f"  --reload-amd-kds bypasses the local AMD KDS cache and re-fetches")
        print(f"  VCEK, CA cert chain, and CRL from kdsintf.amd.com (no effect on TDX).")
        print(f"  --strict fails closed when AMD KDS is unreachable or rate-limited")
        print(f"  instead of falling back to a stale cached entry. No effect on TDX.")
        print(f"  --proof-of-cloud also asks SCRT Labs' quote-parse endpoint to confirm")
        print(f"  the quote originated on a Secret VM (opt-in; off by default).")
        print(f"  --show-compose prints the docker-compose.yaml that was verified,")
        print(f"  after the check list.")
        print(f"  --docker-files / --docker-files-sha256 supply the Dockerfiles archive")
        print(f"  (or its SHA-256) baked into the VM — required for VMs that extend the")
        print(f"  launch measurement with docker-files.")
        print(f"  --version / -V prints secretvm-verify version and exits.")
        sys.exit(1)

    url = sys.argv[1]
    product = _get_opt("--product") or ""

    raw = "--raw" in sys.argv
    json_out = "--json" in sys.argv
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    reload_amd_kds = "--reload-amd-kds" in sys.argv
    strict = "--strict" in sys.argv
    check_poc = "--proof-of-cloud" in sys.argv
    show_compose = "--show-compose" in sys.argv

    docker_files_path = _get_opt("--docker-files")
    docker_files_sha256 = _get_opt("--docker-files-sha256")
    docker_files_bytes = None
    if docker_files_path and not docker_files_sha256:
        with open(docker_files_path, "rb") as f:
            docker_files_bytes = f.read()

    if not (raw or json_out):
        print(f"Verifying {url}\n")
    result = check_secret_vm(
        url,
        product=product,
        reload_amd_kds=reload_amd_kds,
        check_proof_of_cloud=check_poc,
        docker_files=docker_files_bytes,
        docker_files_sha256=docker_files_sha256,
        strict=strict,
    )

    if raw:
        print(json.dumps(asdict(result), indent=2))
        sys.exit(0 if result.valid else 1)
    if json_out:
        minimal = asdict(result)
        minimal.pop("report", None)
        print(json.dumps(minimal, indent=2))
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

    if show_compose and isinstance(result.report.get("docker_compose"), str):
        print("\nDocker compose:")
        print(result.report["docker_compose"])

    # Verdict
    print(f"\n{'✅ All Passed' if result.valid else '🚫 Failed'}")
    sys.exit(0 if result.valid else 1)


if __name__ == "__main__":
    main()
