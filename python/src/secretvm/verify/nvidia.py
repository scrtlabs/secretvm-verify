"""NVIDIA GPU attestation verification."""

import asyncio
import base64
import json

import requests
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate

from .types import AttestationResult

_NRAS_URL = "https://nras.attestation.nvidia.com/v4/attest/gpu"
_NRAS_JWKS_URL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"


def _gpu_decode_jwt_header(token: str) -> dict:
    header_b64 = token.split(".")[0]
    header_b64 += "=" * (-len(header_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(header_b64))


def _gpu_decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _gpu_fetch_jwks() -> dict:
    resp = requests.get(_NRAS_JWKS_URL, timeout=15)
    resp.raise_for_status()
    keys_by_kid = {}
    for key in resp.json().get("keys", []):
        kid = key.get("kid")
        if kid:
            keys_by_kid[kid] = key
    return keys_by_kid


def _gpu_verify_jwt_signature(token: str, jwks: dict) -> bool:
    header = _gpu_decode_jwt_header(token)
    kid = header.get("kid")
    alg = header.get("alg")

    if alg != "ES384":
        return False
    if kid not in jwks:
        return False

    jwk = jwks[kid]
    x5c = jwk.get("x5c", [])
    if x5c:
        cert = load_der_x509_certificate(base64.b64decode(x5c[0]))
        public_key = cert.public_key()
    else:
        x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
        y_bytes = base64.urlsafe_b64decode(jwk["y"] + "==")
        public_key = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x_bytes, "big"),
            y=int.from_bytes(y_bytes, "big"),
            curve=ec.SECP384R1(),
        ).public_key()

    parts = token.split(".")
    signed_data = f"{parts[0]}.{parts[1]}".encode("ascii")
    sig_b64 = parts[2] + "=" * (-len(parts[2]) % 4)
    sig_raw = base64.urlsafe_b64decode(sig_b64)

    r = int.from_bytes(sig_raw[:48], "big")
    s = int.from_bytes(sig_raw[48:], "big")
    der_sig = utils.encode_dss_signature(r, s)

    try:
        public_key.verify(der_sig, signed_data, ec.ECDSA(hashes.SHA384()))
        return True
    except Exception:
        return False


def check_nvidia_gpu_attestation(data_or_url: str) -> AttestationResult:
    """Verify NVIDIA GPU attestation via the NVIDIA Remote Attestation Service.

    Args:
        data_or_url: JSON attestation payload, or a VM URL to fetch the GPU quote from.

    Returns:
        AttestationResult with verification status and parsed attestation claims.
    """
    from .url import is_vm_url, fetch_gpu_quote
    data = fetch_gpu_quote(data_or_url) if is_vm_url(data_or_url) else data_or_url
    errors = []
    checks = {}

    # Parse input
    try:
        attestation_data = json.loads(data)
        checks["input_parsed"] = True
    except Exception as e:
        return AttestationResult(
            valid=False, attestation_type="NVIDIA-GPU",
            checks={"input_parsed": False}, errors=[str(e)],
        )

    # Submit to NRAS
    try:
        resp = requests.post(
            _NRAS_URL, json=attestation_data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=30,
        )
        if resp.status_code != 200:
            errors.append(f"NRAS returned {resp.status_code}: {resp.text[:200]}")
            checks["nras_submission"] = False
            return AttestationResult(
                valid=False, attestation_type="NVIDIA-GPU",
                checks=checks, errors=errors,
            )
        nras_response = resp.json()
        checks["nras_submission"] = True
    except Exception as e:
        errors.append(f"NRAS request failed: {e}")
        checks["nras_submission"] = False
        return AttestationResult(
            valid=False, attestation_type="NVIDIA-GPU",
            checks=checks, errors=errors,
        )

    # Fetch JWKS and verify JWT signatures
    try:
        jwks = _gpu_fetch_jwks()
    except Exception as e:
        errors.append(f"Failed to fetch NVIDIA JWKS: {e}")
        jwks = {}

    report = {}
    all_sigs_valid = True

    # Platform JWT
    jwt_entry = nras_response[0]
    if isinstance(jwt_entry, list) and jwt_entry[0] == "JWT":
        platform_token = jwt_entry[1]
        sig_valid = _gpu_verify_jwt_signature(platform_token, jwks) if jwks else False
        checks["platform_jwt_signature"] = sig_valid
        if not sig_valid:
            all_sigs_valid = False
            errors.append("Platform JWT signature verification failed")

        overall_claims = _gpu_decode_jwt_payload(platform_token)
        report["overall_result"] = overall_claims.get("x-nvidia-overall-att-result")
        report["subject"] = overall_claims.get("sub")
        report["issuer"] = overall_claims.get("iss")
        report["nonce"] = overall_claims.get("eat_nonce")

    # Per-GPU JWTs
    gpu_entries = nras_response[1] if len(nras_response) > 1 else {}
    gpu_reports = {}
    if isinstance(gpu_entries, dict):
        for gpu_id, token in gpu_entries.items():
            sig_valid = _gpu_verify_jwt_signature(token, jwks) if jwks else False
            checks[f"{gpu_id}_jwt_signature"] = sig_valid
            if not sig_valid:
                all_sigs_valid = False
                errors.append(f"{gpu_id} JWT signature verification failed")

            claims = _gpu_decode_jwt_payload(token)
            gpu_reports[gpu_id] = {
                "model": claims.get("hwmodel"),
                "oem_id": claims.get("oemid"),
                "ueid": claims.get("ueid"),
                "debug_status": claims.get("dbgstat"),
                "secure_boot": claims.get("secboot"),
                "driver_version": claims.get("x-nvidia-gpu-driver-version"),
                "vbios_version": claims.get("x-nvidia-gpu-vbios-version"),
                "attestation_report_parsed": claims.get("x-nvidia-gpu-attestation-report-parsed"),
                "attestation_report_signature_verified": claims.get("x-nvidia-gpu-attestation-report-signature-verified"),
                "attestation_report_nonce_match": claims.get("x-nvidia-gpu-attestation-report-nonce-match"),
                "arch_check": claims.get("x-nvidia-gpu-arch-check"),
                "measurements": claims.get("measres"),
            }

    report["gpus"] = gpu_reports

    overall_att_result = report.get("overall_result", False)
    valid = bool(overall_att_result) and all_sigs_valid

    return AttestationResult(
        valid=valid, attestation_type="NVIDIA-GPU",
        checks=checks, report=report, errors=errors,
    )


async def check_nvidia_gpu_attestation_async(data_or_url: str) -> AttestationResult:
    """Async variant of :func:`check_nvidia_gpu_attestation`.

    Use this from inside an event loop. The NVIDIA GPU verification path uses
    sync :mod:`requests` for NRAS submission and JWKS fetching, plus pure-CPU
    JWT signature verification — no async-native operations to bridge — so
    this implementation simply offloads the synchronous function to a thread
    pool via :func:`asyncio.to_thread`.
    """
    return await asyncio.to_thread(check_nvidia_gpu_attestation, data_or_url)
