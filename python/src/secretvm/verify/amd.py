"""AMD SEV-SNP attestation verification."""

import asyncio
import base64
import datetime
import hashlib
import struct

import requests
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    load_der_x509_certificate,
    load_pem_x509_certificate,
    load_der_x509_crl,
)

from .types import AttestationResult
from . import _kds_cache as _cache

_AMD_KDS_BASE = "https://kdsintf.amd.com"
_AMD_REPORT_SIZE = 0x4A0
_AMD_SIG_OFFSET = 0x2A0
_AMD_SIG_COMPONENT_SIZE = 72
_AMD_SIG_VALUE_SIZE = 48


def _amd_parse_tcb(raw: bytes) -> dict:
    return {
        "boot_loader": raw[0],
        "tee": raw[1],
        "snp": raw[6],
        "microcode": raw[7],
    }


def _amd_parse_report(raw: bytes) -> dict:
    if len(raw) < _AMD_REPORT_SIZE:
        raise ValueError(f"Report too short: {len(raw)} bytes (expected {_AMD_REPORT_SIZE})")

    version = struct.unpack_from("<I", raw, 0x000)[0]
    if version < 2:
        raise ValueError(f"Unsupported report version: {version} (expected >= 2)")

    sig_algo = struct.unpack_from("<I", raw, 0x034)[0]
    if sig_algo != 1:
        raise ValueError(f"Unsupported signature algorithm: {sig_algo} (expected 1 = ECDSA-P384-SHA384)")

    policy = struct.unpack_from("<Q", raw, 0x008)[0]
    platform_info = struct.unpack_from("<Q", raw, 0x040)[0]

    sig_r = raw[_AMD_SIG_OFFSET:_AMD_SIG_OFFSET + _AMD_SIG_VALUE_SIZE]
    sig_s = raw[_AMD_SIG_OFFSET + _AMD_SIG_COMPONENT_SIZE:
                _AMD_SIG_OFFSET + _AMD_SIG_COMPONENT_SIZE + _AMD_SIG_VALUE_SIZE]

    return {
        "version": version,
        "guest_svn": struct.unpack_from("<I", raw, 0x004)[0],
        "policy": policy,
        "family_id": raw[0x010:0x020],
        "image_id": raw[0x020:0x030],
        "vmpl": struct.unpack_from("<I", raw, 0x030)[0],
        "signature_algo": sig_algo,
        "current_tcb": _amd_parse_tcb(raw[0x038:0x040]),
        "platform_info": platform_info,
        "author_key_en": struct.unpack_from("<I", raw, 0x048)[0],
        "report_data": raw[0x050:0x090],
        "measurement": raw[0x090:0x0C0],
        "host_data": raw[0x0C0:0x0E0],
        "id_key_digest": raw[0x0E0:0x110],
        "author_key_digest": raw[0x110:0x140],
        "report_id": raw[0x140:0x160],
        "report_id_ma": raw[0x160:0x180],
        "reported_tcb": _amd_parse_tcb(raw[0x180:0x188]),
        "chip_id": raw[0x1A0:0x1E0],
        "committed_tcb": _amd_parse_tcb(raw[0x1E0:0x1E8]),
        "current_build": raw[0x1E8],
        "current_minor": raw[0x1E9],
        "current_major": raw[0x1EA],
        "committed_build": raw[0x1EC],
        "committed_minor": raw[0x1ED],
        "committed_major": raw[0x1EE],
        "launch_tcb": _amd_parse_tcb(raw[0x1F0:0x1F8]),
        "signature_r": sig_r,
        "signature_s": sig_s,
        "raw_report": raw[:_AMD_REPORT_SIZE],
        "smt_allowed": bool(policy & (1 << 16)),
        "debug_allowed": bool(policy & (1 << 19)),
    }


def _amd_vcek_url(product: str, chip_id: bytes, tcb: dict) -> str:
    return (
        f"{_AMD_KDS_BASE}/vcek/v1/{product}/{chip_id.hex()}"
        f"?blSPL={tcb['boot_loader']}&teeSPL={tcb['tee']}"
        f"&snpSPL={tcb['snp']}&ucodeSPL={tcb['microcode']}"
    )


def _vcek_cache_key(product: str, chip_id: bytes, tcb: dict) -> str:
    """Stable cache key for the VCEK fetch — includes the full TCB tuple
    because AMD issues a distinct VCEK per (chip, ucode, snp, tee, bl) level."""
    return (
        f"{product}_{chip_id.hex()}"
        f"_bl{tcb['boot_loader']}_tee{tcb['tee']}"
        f"_snp{tcb['snp']}_uc{tcb['microcode']}"
    )


def _stale_fallback(kind: str, key: str, strict: bool):
    """Return a stale cached entry, or None if strict mode is on."""
    if strict:
        return None
    return _cache.get_stale(kind, key)


def _amd_fetch_vcek(
    product: str,
    chip_id: bytes,
    reported_tcb: dict,
    reload_amd_kds: bool = False,
    strict: bool = False,
):
    """Fetch VCEK cert (cache-first). Auto-detects product if empty.
    Returns (cert_obj, der_bytes, product_name).

    When ``reload_amd_kds`` is True, the cache read is skipped and a fresh
    fetch is performed; the result is still written back to the cache.
    When ``strict`` is True, fail closed instead of falling back to a stale
    cached entry on network failure / 429 / non-200.
    """
    candidates = [product] if product else ["Genoa", "Milan", "Turin"]
    for name in candidates:
        cache_key = _vcek_cache_key(name, chip_id, reported_tcb)
        if not reload_amd_kds:
            cached = _cache.get("vcek", cache_key)
            if cached is not None:
                return load_der_x509_certificate(cached), cached, name
        url = _amd_vcek_url(name, chip_id, reported_tcb)
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            _cache.put("vcek", cache_key, resp.content, _cache.TTL_VCEK_SECONDS)
            return load_der_x509_certificate(resp.content), resp.content, name
        if resp.status_code == 429:
            stale = _stale_fallback("vcek", cache_key, strict)
            if stale is not None:
                return load_der_x509_certificate(stale), stale, name
            raise RuntimeError("AMD KDS rate-limited (429). Retry later or specify product.")
        if product:
            stale = _stale_fallback("vcek", cache_key, strict)
            if stale is not None:
                return load_der_x509_certificate(stale), stale, name
            raise RuntimeError(f"AMD KDS returned {resp.status_code}")
    raise RuntimeError("Could not fetch VCEK for any known product (Genoa/Milan/Turin)")


def _amd_fetch_chain_pem(product: str, reload_amd_kds: bool = False, strict: bool = False) -> bytes:
    """Fetch the AMD CA cert chain (ASK + ARK) for a product, cache-first.

    When ``reload_amd_kds`` is True, the cache read is skipped and a fresh
    fetch is performed; the result is still written back to the cache.
    When ``strict`` is True, fail closed instead of falling back to a stale
    cached entry on network failure or non-200.
    """
    if not reload_amd_kds:
        cached = _cache.get("cert_chain", product)
        if cached is not None:
            return cached
    url = f"{_AMD_KDS_BASE}/vcek/v1/{product}/cert_chain"
    try:
        resp = requests.get(url, timeout=15)
    except Exception:
        stale = _stale_fallback("cert_chain", product, strict)
        if stale is not None:
            return stale
        raise
    if resp.status_code != 200:
        stale = _stale_fallback("cert_chain", product, strict)
        if stale is not None:
            return stale
        raise RuntimeError(f"AMD KDS cert_chain returned {resp.status_code}")
    _cache.put("cert_chain", product, resp.content, _cache.TTL_CHAIN_SECONDS)
    return resp.content


def _amd_fetch_crl(product: str, reload_amd_kds: bool = False, strict: bool = False) -> bytes:
    """Fetch the AMD VCEK CRL for a product, cache-first.

    The CRL is consulted to detect chips that AMD has revoked. The cache TTL
    is computed from the CRL's own X.509 ``nextUpdate`` field, so the cache
    naturally aligns with AMD's published refresh schedule. If the CRL has
    no ``nextUpdate`` (rare) or parsing fails, we fall back to a 7-day TTL.
    On network failure we fall back to a stale cached entry rather than
    failing every SEV verification while KDS is down (unless ``strict`` is
    True, in which case the caller wants to fail closed).
    """
    if not reload_amd_kds:
        cached = _cache.get("crl", product)
        if cached is not None:
            return cached
    url = f"{_AMD_KDS_BASE}/vcek/v1/{product}/crl"
    try:
        resp = requests.get(url, timeout=15)
    except Exception:
        stale = _stale_fallback("crl", product, strict)
        if stale is not None:
            return stale
        raise
    if resp.status_code != 200:
        stale = _stale_fallback("crl", product, strict)
        if stale is not None:
            return stale
        raise RuntimeError(f"AMD KDS crl returned {resp.status_code}")

    # Use the CRL's own nextUpdate as the TTL when available; fall back to
    # the 7-day default when it's missing or parsing fails.
    ttl = _cache.TTL_CRL_SECONDS
    try:
        crl = load_der_x509_crl(resp.content)
        next_update = crl.next_update_utc
        if next_update is not None:
            seconds = int(
                (next_update - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
            )
            if seconds > 0:
                ttl = seconds
    except Exception:
        pass

    _cache.put("crl", product, resp.content, ttl)
    return resp.content


def _amd_check_vcek_revocation(vcek_cert, crl_der: bytes) -> bool:
    """Return True if the VCEK is NOT in the CRL (i.e. not revoked)."""
    crl = load_der_x509_crl(crl_der)
    revoked_serials = {entry.serial_number for entry in crl}
    return vcek_cert.serial_number not in revoked_serials


def _amd_split_pem(pem_data: bytes) -> list[bytes]:
    blocks = []
    pem_str = pem_data.decode("ascii", errors="replace")
    start = 0
    while True:
        begin = pem_str.find("-----BEGIN CERTIFICATE-----", start)
        if begin == -1:
            break
        end = pem_str.find("-----END CERTIFICATE-----", begin)
        if end == -1:
            break
        end += len("-----END CERTIFICATE-----")
        blocks.append(pem_str[begin:end].encode("ascii"))
        start = end
    return blocks


def _amd_verify_one_cert(child, parent) -> bool:
    """Verify that *child* was signed by *parent*, auto-detecting RSA-PSS vs ECDSA."""
    from cryptography.hazmat.primitives.asymmetric import padding, rsa as _rsa
    pub = parent.public_key()
    try:
        if isinstance(pub, _rsa.RSAPublicKey):
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA384()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA384(),
            )
        else:
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA384()),
            )
        return True
    except Exception:
        return False


# Pinned SHA-256 fingerprints of the AMD ARK public keys (SPKI), per product.
#
# AMD publishes the ARK at https://kdsintf.amd.com/vcek/v1/{product}/cert_chain,
# but the chain endpoint is reachable over the public internet — without
# pinning, a DNS-spoof or compromised KDS could substitute a self-signed
# impostor ARK and the chain check would still pass. These fingerprints are
# the cryptographic anchor that ties the chain to AMD.
#
# The pin is over the SubjectPublicKeyInfo (not the cert envelope) so it
# survives certificate reissuance with the same key. ARKs ship with 25-year
# validity (e.g. ARK-Milan: 2020 → 2045).
#
# Recompute by running:
#   curl -sf https://kdsintf.amd.com/vcek/v1/{product}/cert_chain |
#     awk '/-----BEGIN CERTIFICATE-----/{n++} n==2{print}' |
#     openssl x509 -pubkey -noout |
#     openssl pkey -pubin -outform DER 2>/dev/null |
#     openssl dgst -sha256
_PINNED_ARK_SPKI_SHA256 = {
    "Milan": "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9",
    "Genoa": "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831",
    "Turin": "4f125410563a2ab9a50356f9243f6fe0b6f73de98603f53f90339c70e9d7ad08",
}


def _amd_spki_sha256_hex(cert) -> str:
    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


def _amd_verify_cert_chain(vcek_der: bytes, chain_pem: bytes, product: str) -> bool:
    """Verify VCEK -> ASK -> ARK certificate chain and pin the ARK to AMD."""
    pem_blocks = _amd_split_pem(chain_pem)
    if len(pem_blocks) < 2:
        return False

    vcek = load_der_x509_certificate(vcek_der)
    ask = load_pem_x509_certificate(pem_blocks[0])
    ark = load_pem_x509_certificate(pem_blocks[1])

    now = datetime.datetime.now(datetime.timezone.utc)
    for cert in [vcek, ask, ark]:
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return False

    # Pin the ARK to the known AMD root for this product. Without this,
    # a self-signed impostor chain would pass the cryptographic checks below.
    expected_ark_spki = _PINNED_ARK_SPKI_SHA256.get(product)
    if not expected_ark_spki:
        return False
    if _amd_spki_sha256_hex(ark) != expected_ark_spki:
        return False

    # ARK is self-signed, ASK signed by ARK, VCEK signed by ASK
    return (
        _amd_verify_one_cert(ark, ark)
        and _amd_verify_one_cert(ask, ark)
        and _amd_verify_one_cert(vcek, ask)
    )


def _amd_verify_report_signature(rpt: dict, vcek_cert) -> bool:
    pub_key = vcek_cert.public_key()
    signed_data = rpt["raw_report"][:_AMD_SIG_OFFSET]
    r = int.from_bytes(rpt["signature_r"], "little")
    s = int.from_bytes(rpt["signature_s"], "little")
    if r == 0 and s == 0:
        return False
    der_sig = utils.encode_dss_signature(r, s)
    try:
        pub_key.verify(der_sig, signed_data, ec.ECDSA(hashes.SHA384()))
        return True
    except Exception:
        return False


def check_sev_cpu_attestation(
    data_or_url: str,
    product: str = "",
    reload_amd_kds: bool = False,
    strict: bool = False,
) -> AttestationResult:
    """Verify an AMD SEV-SNP attestation report.

    Args:
        data_or_url: Base64-encoded attestation report, or a VM URL to fetch the quote from.
        product: AMD product name (Genoa, Milan, Turin). Auto-detected if empty.
        reload_amd_kds: If True, bypass the local cache and re-fetch the
            VCEK, AMD CA cert chain, and CRL from kdsintf.amd.com. The fresh
            data is written back to the cache so subsequent calls are fast.
        strict: If True, fail closed when AMD KDS is unreachable or
            rate-limited rather than falling back to a stale cached entry.
            Trades availability for freshness.

    Returns:
        AttestationResult with verification status and parsed report fields.
    """
    from .url import is_vm_url, fetch_cpu_quote
    data = fetch_cpu_quote(data_or_url) if is_vm_url(data_or_url) else data_or_url
    errors = []
    checks = {}

    # Decode input (try hex first, then base64)
    try:
        text = data.strip()
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = base64.b64decode(text)
        rpt = _amd_parse_report(raw)
        checks["report_parsed"] = True
    except Exception as e:
        return AttestationResult(
            valid=False, attestation_type="SEV-SNP",
            checks={"report_parsed": False}, errors=[str(e)],
        )

    # Fetch VCEK
    try:
        vcek, vcek_der, detected_product = _amd_fetch_vcek(
            product, rpt["chip_id"], rpt["reported_tcb"],
            reload_amd_kds=reload_amd_kds, strict=strict,
        )
        checks["vcek_fetched"] = True
    except Exception as e:
        errors.append(f"Failed to fetch VCEK: {e}")
        checks["vcek_fetched"] = False
        return AttestationResult(
            valid=False, attestation_type="SEV-SNP",
            checks=checks, errors=errors,
        )

    # Verify cert chain (VCEK -> ASK -> ARK)
    try:
        chain_pem = _amd_fetch_chain_pem(detected_product, reload_amd_kds=reload_amd_kds, strict=strict)
        checks["cert_chain_valid"] = _amd_verify_cert_chain(vcek_der, chain_pem, detected_product)
        if not checks["cert_chain_valid"]:
            errors.append("Certificate chain verification failed (VCEK -> ASK -> ARK)")
    except Exception as e:
        checks["cert_chain_valid"] = False
        errors.append(f"Failed to verify cert chain: {e}")

    # CRL revocation check — fetch the AMD VCEK CRL and confirm the leaf
    # cert's serial number is not in the revoked list. Cached for 7 days.
    try:
        crl_der = _amd_fetch_crl(detected_product, reload_amd_kds=reload_amd_kds, strict=strict)
        checks["crl_check_passed"] = _amd_check_vcek_revocation(vcek, crl_der)
        if not checks["crl_check_passed"]:
            errors.append(
                f"VCEK serial {vcek.serial_number:x} is revoked per AMD CRL"
            )
    except Exception as e:
        checks["crl_check_passed"] = False
        errors.append(f"CRL revocation check failed: {e}")

    # Verify report signature
    checks["report_signature_valid"] = _amd_verify_report_signature(rpt, vcek)
    if not checks["report_signature_valid"]:
        errors.append("Report signature verification failed")

    valid = all([
        checks.get("report_parsed"),
        checks.get("vcek_fetched"),
        checks.get("cert_chain_valid"),
        checks.get("crl_check_passed"),
        checks.get("report_signature_valid"),
    ])

    report = {
        "version": rpt["version"],
        "guest_svn": rpt["guest_svn"],
        "vmpl": rpt["vmpl"],
        "policy": f"0x{rpt['policy']:016x}",
        "smt_allowed": rpt["smt_allowed"],
        "debug_allowed": rpt["debug_allowed"],
        "family_id": rpt["family_id"].hex(),
        "image_id": rpt["image_id"].hex(),
        "measurement": rpt["measurement"].hex(),
        "report_data": rpt["report_data"].hex(),
        "host_data": rpt["host_data"].hex(),
        "id_key_digest": rpt["id_key_digest"].hex(),
        "author_key_digest": rpt["author_key_digest"].hex(),
        "report_id": rpt["report_id"].hex(),
        "chip_id": rpt["chip_id"].hex(),
        "current_tcb": rpt["current_tcb"],
        "reported_tcb": rpt["reported_tcb"],
        "committed_tcb": rpt["committed_tcb"],
        "launch_tcb": rpt["launch_tcb"],
        "current_firmware": f"{rpt['current_major']}.{rpt['current_minor']} (build {rpt['current_build']})",
        "platform_info": f"0x{rpt['platform_info']:016x}",
        "product": detected_product,
    }

    return AttestationResult(
        valid=valid, attestation_type="SEV-SNP",
        checks=checks, report=report, errors=errors,
    )


async def check_sev_cpu_attestation_async(
    data_or_url: str,
    product: str = "",
    reload_amd_kds: bool = False,
    strict: bool = False,
) -> AttestationResult:
    """Async variant of :func:`check_sev_cpu_attestation`.

    Use this from inside an event loop (FastAPI handlers, Jupyter notebooks,
    other async frameworks). The SEV-SNP verification path has no async-native
    operations — it uses sync :mod:`requests` for AMD KDS and pure-CPU crypto —
    so this implementation simply offloads the synchronous function to a
    thread pool via :func:`asyncio.to_thread`. The event loop is not blocked
    while the AMD KDS round-trip and signature verification run.
    """
    return await asyncio.to_thread(
        check_sev_cpu_attestation, data_or_url, product, reload_amd_kds, strict,
    )
