"""Secret VM end-to-end verification (CPU + GPU + binding checks)."""

import asyncio
import hashlib
import json
import ssl
import sys
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_pem_x509_certificate

from .types import AttestationResult

_SECRET_VM_PORT = 29343


def _get_tls_cert_fingerprint(host: str, port: int) -> bytes:
    """Connect to host:port and return SHA-256 of the server's DER certificate."""
    pem = ssl.get_server_certificate((host, port))
    cert = load_pem_x509_certificate(pem.encode("ascii"))
    der = cert.public_bytes(Encoding.DER)
    return hashlib.sha256(der).digest()


def _parse_vm_url(url: str) -> tuple[str, int]:
    """Extract host and port from a URL, defaulting to port 29343."""
    if "://" not in url:
        url = f"https://{url}"
    parsed = urlparse(url)
    host = parsed.hostname or parsed.path
    port = parsed.port or _SECRET_VM_PORT
    return host, port


def _extract_docker_compose(raw: str) -> str:
    """Extract YAML from an HTML-wrapped response.

    The VM serves docker-compose inside a <pre> tag with HTML-encoded entities.
    """
    import html
    import re

    text = raw.strip()
    m = re.search(r"<pre>(.*?)</pre>", text, re.DOTALL | re.IGNORECASE)
    if m:
        text = m.group(1)
    text = html.unescape(text)
    # Strip zero-width spaces and other invisible Unicode characters
    text = re.sub(r"[\u200b\u200c\u200d\ufeff]", "", text)
    return text


def _get_pkg():
    """Return the secretvm.verify package module for late-bound lookups.

    This allows tests to mock functions at the package level
    (e.g. ``patch('secretvm.verify._get_tls_cert_fingerprint', ...)``).
    """
    return sys.modules["secretvm.verify"]


def check_secret_vm(
    url: str,
    product: str = "",
    reload_amd_kds: bool = False,
) -> AttestationResult:
    """Verify a Secret VM by fetching CPU and GPU attestation from its endpoints.

    Connects to the VM's attestation service at <url>:29343, fetches the CPU
    quote from /cpu and (optionally) the GPU quote from /gpu, verifies both,
    and checks the binding between:
      - The TLS certificate fingerprint and the first half of report_data
      - The GPU nonce and the second half of report_data (if GPU is present)

    Args:
        url: VM address (e.g. "https://host:29343", "host:29343", or just "host").
        product: AMD product name (only used for SEV-SNP). Auto-detected if empty.
        reload_amd_kds: If True, bypass the local AMD KDS cache and re-fetch
            VCEK / cert chain / CRL. No effect on TDX VMs (TDX doesn't cache).

    Returns:
        AttestationResult with attestation_type="SECRET-VM".
    """
    # Use late-bound lookups so tests can mock at the package level
    pkg = _get_pkg()

    errors = []
    checks = {}
    report = {}

    host, port = _parse_vm_url(url)
    base_url = f"https://{host}:{port}"

    # 1. Get TLS certificate fingerprint
    try:
        tls_fingerprint = pkg._get_tls_cert_fingerprint(host, port)
        checks["tls_cert_obtained"] = True
        report["tls_fingerprint"] = tls_fingerprint.hex()
    except Exception as e:
        errors.append(f"Failed to get TLS certificate: {e}")
        checks["tls_cert_obtained"] = False
        return AttestationResult(
            valid=False, attestation_type="SECRET-VM",
            checks=checks, report=report, errors=errors,
        )

    # 2. Fetch and verify CPU quote
    try:
        resp = pkg.requests.get(f"{base_url}/cpu", timeout=15, verify=True)
        resp.raise_for_status()
        cpu_data = resp.text
        checks["cpu_quote_fetched"] = True
    except Exception as e:
        errors.append(f"Failed to fetch CPU quote: {e}")
        checks["cpu_quote_fetched"] = False
        return AttestationResult(
            valid=False, attestation_type="SECRET-VM",
            checks=checks, report=report, errors=errors,
        )

    cpu_result = pkg.check_cpu_attestation(
        cpu_data, product=product, reload_amd_kds=reload_amd_kds,
    )
    checks["cpu_attestation_valid"] = cpu_result.valid
    # Propagate the inner DCAP/QVL verification verdict so callers (and the CLI)
    # can surface it prominently. Only TDX currently uses dcap-qvl; SEV results
    # don't populate this key.
    if "quote_verified" in cpu_result.checks:
        checks["cpu_quote_verified"] = cpu_result.checks["quote_verified"]
    report["cpu"] = cpu_result.report
    report["cpu_type"] = cpu_result.attestation_type
    if not cpu_result.valid:
        errors.extend(cpu_result.errors)

    # 3. Check TLS binding: first 32 bytes of report_data == SHA-256(TLS cert)
    report_data_hex = cpu_result.report.get("report_data", "")
    if len(report_data_hex) >= 64:
        first_half = report_data_hex[:64]  # first 32 bytes as hex
        checks["tls_binding"] = first_half == tls_fingerprint.hex()
        if not checks["tls_binding"]:
            errors.append(
                f"TLS binding failed: report_data first half ({first_half[:16]}...) "
                f"!= TLS fingerprint ({tls_fingerprint.hex()[:16]}...)"
            )
    else:
        checks["tls_binding"] = False
        errors.append("report_data too short for TLS binding check")

    # 4. Fetch and verify GPU quote (optional)
    gpu_present = False
    try:
        resp = pkg.requests.get(f"{base_url}/gpu", timeout=15, verify=True)
        resp.raise_for_status()
        gpu_data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else json.loads(resp.text)
        if "error" in gpu_data:
            # Non-GPU machine: {"error": "...", "details": "..."}
            checks["gpu_quote_fetched"] = False
        else:
            gpu_present = True
            checks["gpu_quote_fetched"] = True
            gpu_data = resp.text  # pass raw JSON text to check_nvidia_gpu_attestation
    except Exception:
        checks["gpu_quote_fetched"] = False

    if gpu_present:
        gpu_result = pkg.check_nvidia_gpu_attestation(gpu_data)
        checks["gpu_attestation_valid"] = gpu_result.valid
        report["gpu"] = gpu_result.report
        if not gpu_result.valid:
            errors.extend(gpu_result.errors)

        # 5. Check GPU binding: second 32 bytes of report_data == GPU nonce
        gpu_json = json.loads(gpu_data)
        gpu_nonce = gpu_json.get("nonce", "")
        if len(report_data_hex) >= 128:
            second_half = report_data_hex[64:128]  # second 32 bytes as hex
            checks["gpu_binding"] = second_half == gpu_nonce
            if not checks["gpu_binding"]:
                errors.append(
                    f"GPU binding failed: report_data second half ({second_half[:16]}...) "
                    f"!= GPU nonce ({gpu_nonce[:16]}...)"
                )
        else:
            checks["gpu_binding"] = False
            errors.append("report_data too short for GPU binding check")

    # 6. Fetch and verify workload (docker-compose)
    try:
        resp = pkg.requests.get(f"{base_url}/docker-compose", timeout=15, verify=True)
        resp.raise_for_status()
        docker_compose = _extract_docker_compose(resp.text)
        checks["workload_fetched"] = True

        workload_result = pkg.verify_workload(cpu_data, docker_compose)
        checks["workload_verified"] = workload_result.status == "authentic_match"
        report["workload"] = {
            "status": workload_result.status,
            "template_name": workload_result.template_name,
            "artifacts_ver": workload_result.artifacts_ver,
            "env": workload_result.env,
        }
        if workload_result.status == "authentic_mismatch":
            errors.append("Workload mismatch: VM is authentic but docker-compose does not match")
        elif workload_result.status == "not_authentic":
            errors.append("Workload verification failed: not an authentic SecretVM")
    except Exception as e:
        errors.append(f"Failed to fetch workload: {e}")
        checks["workload_fetched"] = False

    # Overall validity
    required_checks = [
        checks.get("tls_cert_obtained"),
        checks.get("cpu_quote_fetched"),
        checks.get("cpu_attestation_valid"),
        checks.get("tls_binding"),
        checks.get("workload_verified", False),
    ]
    if gpu_present:
        required_checks.append(checks.get("gpu_attestation_valid"))
        required_checks.append(checks.get("gpu_binding"))

    valid = all(required_checks)

    return AttestationResult(
        valid=valid, attestation_type="SECRET-VM",
        checks=checks, report=report, errors=errors,
    )


async def check_secret_vm_async(
    url: str,
    product: str = "",
    reload_amd_kds: bool = False,
) -> AttestationResult:
    """Async variant of :func:`check_secret_vm`.

    Use this from inside an event loop. The current implementation offloads
    the synchronous wrapper to a thread pool via :func:`asyncio.to_thread`,
    so the event loop is not blocked while the TLS, CPU, GPU, and workload
    fetches run sequentially in the worker thread. A future refactor could
    parallelize the four fetches for additional speedup, but the simple
    wrapper is sufficient to use the API from async contexts today.
    """
    return await asyncio.to_thread(check_secret_vm, url, product, reload_amd_kds)
