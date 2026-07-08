"""Secret VM end-to-end verification (CPU + GPU + binding checks)."""

import asyncio
import hashlib
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote, urlparse

import requests
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_der_x509_certificate

from .types import AttestationResult, order_checks

_SECRET_VM_PORT = 29343
_SECRET_VM_RESOURCE_PATHS = {"cpu", "gpu", "docker-compose"}


@dataclass(frozen=True)
class _Endpoint:
    host: str
    port: int
    path_prefix: str
    base_url: str


def _get_tls_cert_digests(host: str, port: int) -> tuple[bytes, bytes]:
    """Connect to host:port and return (SHA-256 of SPKI DER, SHA-256 of full cert DER).

    The SPKI digest is the current binding (stable across cert renewals); the full
    certificate digest is the legacy binding. Accepting either keeps a mixed fleet
    verifiable. The platform trust store is enforced (create_default_context) before
    hashing anything.
    """
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
    if not der:
        raise ssl.SSLError("No certificate received")
    cert = load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).digest(), hashlib.sha256(der).digest()


def _get_tls_cert_fingerprint(host: str, port: int) -> bytes:
    """Return SHA-256 of the certificate SPKI DER (kept for backward compatibility)."""
    return _get_tls_cert_digests(host, port)[0]


def _classify_tls_binding(first_half_hex: str, spki: bytes, cert: bytes):
    """Return (verified, kind) for report_data's first 32 bytes against either digest.

    kind is "spki" (current) or "certificate" (legacy); None when unverified.
    """
    if first_half_hex == spki.hex():
        return True, "spki"
    if first_half_hex == cert.hex():
        return True, "certificate"
    return False, None


def _format_url_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _normalize_endpoint(endpoint: str) -> str:
    endpoint = endpoint.strip()
    if "://" not in endpoint:
        endpoint = f"https://{endpoint}"
    return endpoint


def _path_prefix(path: str) -> str:
    trimmed = path.rstrip("/")
    return "" if trimmed in ("", "/") else trimmed


def _decode_path_segments(path_prefix: str, label: str) -> list[str]:
    segments = [segment for segment in path_prefix.split("/") if segment]
    decoded = []
    for segment in segments:
        if re.search(r"%(?![0-9A-Fa-f]{2})", segment):
            raise ValueError(f"{label} contains invalid percent-encoding")
        item = unquote(segment, errors="strict")
        if "/" in item or "\\" in item:
            raise ValueError(f"{label} must not contain encoded path separators")
        decoded.append(item)
    return decoded


def _parse_service_base_url(
    endpoint: str,
    default_port: int = _SECRET_VM_PORT,
    label: str = "SecretVM endpoint URL",
) -> _Endpoint:
    normalized = _normalize_endpoint(endpoint)
    parsed = urlparse(normalized)
    if parsed.scheme != "https":
        raise ValueError(f"{label} must use https://")
    if parsed.username or parsed.password:
        raise ValueError(f"{label} must not include userinfo")
    if parsed.query:
        raise ValueError(f"{label} must not include a query string")
    if parsed.fragment:
        raise ValueError(f"{label} must not include a fragment")
    if not parsed.hostname:
        raise ValueError(f"{label} must include a host")

    path_prefix = _path_prefix(parsed.path)
    decoded_segments = _decode_path_segments(path_prefix, label)
    if decoded_segments and decoded_segments[-1] in _SECRET_VM_RESOURCE_PATHS:
        raise ValueError(
            f"{label} must be a service base URL, not a concrete /{decoded_segments[-1]} resource path"
        )

    try:
        parsed_port = parsed.port
    except ValueError as e:
        raise ValueError(f"{label} has an invalid port") from e
    port = parsed_port if parsed_port is not None else default_port
    if port < 1 or port > 65535:
        raise ValueError(f"{label} has an invalid port")
    base_url = f"https://{_format_url_host(parsed.hostname)}:{port}{path_prefix}"
    return _Endpoint(host=parsed.hostname, port=port, path_prefix=path_prefix, base_url=base_url)


def _parse_tls_endpoint(endpoint: str, label: str = "TLS endpoint URL") -> _Endpoint:
    parsed = _parse_service_base_url(endpoint, default_port=443, label=label)
    if parsed.path_prefix:
        raise ValueError(f"{label} must not include a path")
    return parsed


def _parse_vm_url(url: str) -> tuple[str, int]:
    """Extract host and port from a URL, defaulting to port 29343."""
    parsed = _parse_service_base_url(url)
    return parsed.host, parsed.port


def _extract_docker_compose(raw: str) -> str:
    """Legacy helper for old HTML-wrapped compose endpoints."""
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
    check_proof_of_cloud: bool = False,
    docker_files: Optional[bytes] = None,
    docker_files_sha256: Optional[str] = None,
    strict: bool = False,
    enforce_gpu: bool = False,
) -> AttestationResult:
    """Verify a Secret VM by fetching CPU and GPU attestation from its endpoints.

    Connects to the VM's attestation service base URL, fetches the CPU
    quote from /cpu and the GPU quote from /gpu, verifies both,
    and checks the binding between:
      - The TLS certificate SPKI digest and the first half of report_data
      - The GPU nonce and the second half of report_data

    Args:
        url: VM attestation service base URL (e.g. "https://host:21434",
            "https://host:29343", or just "host").
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

    try:
        endpoint = _parse_service_base_url(url)
    except Exception as e:
        errors.append(f"Invalid SecretVM endpoint URL: {e}")
        return AttestationResult(
            valid=False, attestation_type="SECRET-VM",
            checks=order_checks(checks), report=report, errors=errors,
        )

    host, port = endpoint.host, endpoint.port
    base_url = endpoint.base_url

    # 1. Get TLS certificate digests (SPKI + full certificate, for backward compat)
    try:
        tls_spki_fingerprint, tls_cert_fingerprint = pkg._get_tls_cert_digests(host, port)
        checks["tls_cert_fetched"] = True
        report["tls_spki_fingerprint"] = tls_spki_fingerprint.hex()
        report["tls_certificate_fingerprint"] = tls_cert_fingerprint.hex()
    except Exception as e:
        errors.append(f"Failed to get TLS certificate: {e}")
        checks["tls_cert_fetched"] = False
        return AttestationResult(
            valid=False, attestation_type="SECRET-VM",
            checks=order_checks(checks), report=report, errors=errors,
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
            checks=order_checks(checks), report=report, errors=errors,
        )

    cpu_result = pkg.check_cpu_attestation(
        cpu_data, product=product, reload_amd_kds=reload_amd_kds, strict=strict,
    )
    checks["cpu_quote_verified"] = cpu_result.valid
    report["cpu"] = cpu_result.report
    report["cpu_type"] = cpu_result.attestation_type
    if not cpu_result.valid:
        errors.extend(cpu_result.errors)

    # 3. Check TLS binding: first 32 bytes of report_data == SHA-256(SPKI DER)
    #    [current] or SHA-256(full certificate DER) [legacy]. Accept either.
    report_data_hex = cpu_result.report.get("report_data", "")
    if len(report_data_hex) >= 64:
        first_half = report_data_hex[:64]  # first 32 bytes as hex
        verified, kind = _classify_tls_binding(first_half, tls_spki_fingerprint, tls_cert_fingerprint)
        checks["tls_binding_verified"] = verified
        if verified:
            report["tls_binding_kind"] = kind
        else:
            errors.append(
                f"TLS binding failed: report_data first half ({first_half[:16]}...) "
                f"!= TLS SPKI ({tls_spki_fingerprint.hex()[:16]}...) "
                f"or certificate ({tls_cert_fingerprint.hex()[:16]}...) digest"
            )
    else:
        checks["tls_binding_verified"] = False
        errors.append("report_data too short for TLS binding check")

    # 4. Fetch and verify GPU quote (optional). GPU is only required when enforce_gpu is set.
    gpu_present = False
    gpu_data = ""
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
        checks["gpu_quote_verified"] = gpu_result.valid
        report["gpu"] = gpu_result.report
        if not gpu_result.valid:
            errors.extend(gpu_result.errors)

        # 5. Check GPU binding: second 32 bytes of report_data == GPU nonce
        gpu_json = json.loads(gpu_data)
        gpu_nonce = gpu_json.get("nonce", "")
        if len(report_data_hex) >= 128:
            second_half = report_data_hex[64:128]  # second 32 bytes as hex
            checks["gpu_binding_verified"] = second_half == gpu_nonce
            if not checks["gpu_binding_verified"]:
                errors.append(
                    f"GPU binding failed: report_data second half ({second_half[:16]}...) "
                    f"!= GPU nonce ({gpu_nonce[:16]}...)"
                )
        else:
            checks["gpu_binding_verified"] = False
            errors.append("report_data too short for GPU binding check")

    # 5b. GPU enforcement (opt-in): when enforce_gpu is set, a GPU must be present,
    # so a CPU-only VM fails closed instead of silently passing.
    if enforce_gpu:
        checks["gpu_present"] = gpu_present
        if not gpu_present:
            errors.append(
                "GPU attestation required (--enforce-gpu) but this VM exposes no GPU"
            )

    # 6. Fetch and verify workload (docker-compose)
    try:
        resp = pkg.requests.get(f"{base_url}/docker-compose", timeout=15, verify=True)
        resp.raise_for_status()
        docker_compose = resp.text
        checks["workload_fetched"] = True

        workload_result = pkg.verify_workload(
            cpu_data, docker_compose, docker_files, docker_files_sha256,
        )
        checks["workload_binding_verified"] = workload_result.status == "authentic_match"
        report["workload"] = {
            "status": workload_result.status,
            "template_name": workload_result.template_name,
            "artifacts_ver": workload_result.artifacts_ver,
            "env": workload_result.env,
        }
        report["docker_compose"] = docker_compose
        if workload_result.status == "authentic_mismatch":
            errors.append("Workload mismatch: VM is authentic but docker-compose does not match")
        elif workload_result.status == "not_authentic":
            errors.append("Workload verification failed: not an authentic SecretVM")
    except Exception as e:
        errors.append(f"Failed to fetch workload: {e}")
        checks["workload_fetched"] = False

    # 7. Proof of cloud (opt-in): ask the community trust-server peers whether
    # this machine is on the Proof of Cloud whitelist. Disabled by default — set
    # check_proof_of_cloud=True (or --proof-of-cloud on the CLI) to include.
    if check_proof_of_cloud:
        poc_result = pkg.check_proof_of_cloud(cpu_data)
        checks["proof_of_cloud_verified"] = poc_result.valid
        if poc_result.report.get("proof_of_cloud") is not None:
            report["proof_of_cloud"] = poc_result.report["proof_of_cloud"]
        if not poc_result.valid:
            errors.extend(poc_result.errors)

    # Overall validity
    required_checks = [
        checks.get("tls_cert_fetched"),
        checks.get("cpu_quote_fetched"),
        checks.get("cpu_quote_verified"),
        checks.get("tls_binding_verified"),
        checks.get("workload_binding_verified", False),
    ]
    if check_proof_of_cloud:
        required_checks.append(checks.get("proof_of_cloud_verified", False))
    if enforce_gpu:
        required_checks.append(checks.get("gpu_present", False))
    if gpu_present:
        required_checks.append(checks.get("gpu_quote_verified"))
        required_checks.append(checks.get("gpu_binding_verified"))

    valid = all(required_checks)

    return AttestationResult(
        valid=valid, attestation_type="SECRET-VM",
        checks=order_checks(checks), report=report, errors=errors,
    )


async def check_secret_vm_async(
    url: str,
    product: str = "",
    reload_amd_kds: bool = False,
    check_proof_of_cloud: bool = False,
    docker_files: Optional[bytes] = None,
    docker_files_sha256: Optional[str] = None,
    strict: bool = False,
    enforce_gpu: bool = False,
) -> AttestationResult:
    """Async variant of :func:`check_secret_vm`.

    Use this from inside an event loop. The current implementation offloads
    the synchronous wrapper to a thread pool via :func:`asyncio.to_thread`,
    so the event loop is not blocked while the TLS, CPU, GPU, and workload
    fetches run sequentially in the worker thread. A future refactor could
    parallelize the four fetches for additional speedup, but the simple
    wrapper is sufficient to use the API from async contexts today.
    """
    return await asyncio.to_thread(
        check_secret_vm, url, product, reload_amd_kds, check_proof_of_cloud,
        docker_files, docker_files_sha256, strict, enforce_gpu,
    )
