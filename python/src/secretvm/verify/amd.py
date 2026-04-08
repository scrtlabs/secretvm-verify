"""AMD SEV-SNP attestation verification."""

import base64
import datetime
import struct

import requests
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate

from .types import AttestationResult

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


def _amd_fetch_vcek(product: str, chip_id: bytes, reported_tcb: dict):
    """Fetch VCEK cert from AMD KDS. Auto-detects product if empty.
    Returns (cert_obj, der_bytes, product_name).
    """
    candidates = [product] if product else ["Genoa", "Milan", "Turin"]
    for name in candidates:
        url = _amd_vcek_url(name, chip_id, reported_tcb)
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            return load_der_x509_certificate(resp.content), resp.content, name
        if resp.status_code == 429:
            raise RuntimeError("AMD KDS rate-limited (429). Retry later or specify product.")
        if product:
            raise RuntimeError(f"AMD KDS returned {resp.status_code}")
    raise RuntimeError("Could not fetch VCEK for any known product (Genoa/Milan/Turin)")


def _amd_fetch_chain_pem(product: str) -> bytes:
    url = f"{_AMD_KDS_BASE}/vcek/v1/{product}/cert_chain"
    resp = requests.get(url, timeout=15)
    if resp.status_code != 200:
        raise RuntimeError(f"AMD KDS cert_chain returned {resp.status_code}")
    return resp.content


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


def _amd_verify_cert_chain(vcek_der: bytes, chain_pem: bytes) -> bool:
    """Verify VCEK -> ASK -> ARK certificate chain using native crypto."""
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


def check_sev_cpu_attestation(data_or_url: str, product: str = "") -> AttestationResult:
    """Verify an AMD SEV-SNP attestation report.

    Args:
        data_or_url: Base64-encoded attestation report, or a VM URL to fetch the quote from.
        product: AMD product name (Genoa, Milan, Turin). Auto-detected if empty.

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
            product, rpt["chip_id"], rpt["reported_tcb"]
        )
        checks["vcek_fetched"] = True
    except Exception as e:
        errors.append(f"Failed to fetch VCEK: {e}")
        checks["vcek_fetched"] = False
        return AttestationResult(
            valid=False, attestation_type="SEV-SNP",
            checks=checks, errors=errors,
        )

    # Verify cert chain via openssl
    try:
        chain_pem = _amd_fetch_chain_pem(detected_product)
        checks["cert_chain_valid"] = _amd_verify_cert_chain(vcek_der, chain_pem)
        if not checks["cert_chain_valid"]:
            errors.append("Certificate chain verification failed (VCEK -> ASK -> ARK)")
    except Exception as e:
        checks["cert_chain_valid"] = False
        errors.append(f"Failed to verify cert chain: {e}")

    # Verify report signature
    checks["report_signature_valid"] = _amd_verify_report_signature(rpt, vcek)
    if not checks["report_signature_valid"]:
        errors.append("Report signature verification failed")

    valid = all([
        checks.get("report_parsed"),
        checks.get("vcek_fetched"),
        checks.get("cert_chain_valid"),
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
