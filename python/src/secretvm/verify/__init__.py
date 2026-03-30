"""
Attestation verification library for Intel TDX, AMD SEV-SNP, and NVIDIA GPU.

Public API:
    check_secret_vm(url: str, product: str = "") -> AttestationResult
    check_cpu_attestation(data: str, product: str = "") -> AttestationResult
    check_tdx_cpu_attestation(data: str) -> AttestationResult
    check_amd_cpu_attestation(data: str, product: str = "") -> AttestationResult
    check_nvidia_gpu_attestation(data: str) -> AttestationResult

Each function accepts the raw text content of the attestation quote file
(hex-encoded for TDX, base64-encoded for AMD, JSON for NVIDIA) and returns
an AttestationResult with verification status, individual checks, parsed
report fields, and any errors.
"""

import base64
import hashlib
import json
import ssl
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate


# ---------------------------------------------------------------------------
# Public result type
# ---------------------------------------------------------------------------

@dataclass
class AttestationResult:
    valid: bool
    attestation_type: str  # "TDX", "SEV-SNP", "NVIDIA-GPU"
    checks: dict = field(default_factory=dict)
    report: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


# ===========================================================================
#
#  INTEL TDX
#
# ===========================================================================

_INTEL_PCS_BASE = "https://api.trustedservices.intel.com/sgx/certification/v4"


def _tdx_parse_quote(raw: bytes) -> dict:
    """Parse a TDX Quote v4 and return header, td_report, and signature data."""
    if len(raw) < 632:
        raise ValueError(f"Quote too short: {len(raw)} bytes (minimum 632)")

    version, att_key_type, tee_type = struct.unpack_from("<HHI", raw, 0)
    qe_svn, pce_svn = struct.unpack_from("<HH", raw, 8)
    qe_vendor_id = raw[12:28]
    user_data = raw[28:48]

    if version != 4:
        raise ValueError(f"Unsupported quote version: {version}")
    if tee_type != 0x81:
        raise ValueError(f"Not a TDX quote (tee_type=0x{tee_type:x})")

    raw_header = raw[0:48]

    # TD Report Body: 584 bytes at offset 48
    off = 48
    raw_td_report = raw[off:off + 584]
    td = {
        "tee_tcb_svn": raw[off:off + 16],
        "mr_seam": raw[off + 16:off + 64],
        "mr_signer_seam": raw[off + 64:off + 112],
        "seam_attributes": raw[off + 112:off + 120],
        "td_attributes": raw[off + 120:off + 128],
        "xfam": raw[off + 128:off + 136],
        "mr_td": raw[off + 136:off + 184],
        "mr_config_id": raw[off + 184:off + 232],
        "mr_owner": raw[off + 232:off + 280],
        "mr_owner_config": raw[off + 280:off + 328],
        "rt_mr0": raw[off + 328:off + 376],
        "rt_mr1": raw[off + 376:off + 424],
        "rt_mr2": raw[off + 424:off + 472],
        "rt_mr3": raw[off + 472:off + 520],
        "report_data": raw[off + 520:off + 584],
    }

    # Signature Data at offset 632
    off = 632
    sig_data_len = struct.unpack_from("<I", raw, off)[0]
    off += 4

    quote_sig = raw[off:off + 64]; off += 64
    att_pub_key = raw[off:off + 64]; off += 64

    outer_cert_type = struct.unpack_from("<H", raw, off)[0]; off += 2
    outer_cert_size = struct.unpack_from("<I", raw, off)[0]; off += 4
    outer_cert_data = raw[off:off + outer_cert_size]

    if outer_cert_type == 6:
        coff = 0
        qe_report = outer_cert_data[coff:coff + 384]; coff += 384
        qe_report_sig = outer_cert_data[coff:coff + 64]; coff += 64
        qe_auth_len = struct.unpack_from("<H", outer_cert_data, coff)[0]; coff += 2
        qe_auth_data = outer_cert_data[coff:coff + qe_auth_len]; coff += qe_auth_len
        cert_data_type = struct.unpack_from("<H", outer_cert_data, coff)[0]; coff += 2
        cert_data_len = struct.unpack_from("<I", outer_cert_data, coff)[0]; coff += 4
        cert_data = outer_cert_data[coff:coff + cert_data_len]
    else:
        qe_report = outer_cert_data[0:384]
        qe_report_sig = outer_cert_data[384:448]
        coff = 448
        qe_auth_len = struct.unpack_from("<H", outer_cert_data, coff)[0]; coff += 2
        qe_auth_data = outer_cert_data[coff:coff + qe_auth_len]; coff += qe_auth_len
        cert_data_type = outer_cert_type
        cert_data = outer_cert_data

    return {
        "version": version,
        "att_key_type": att_key_type,
        "tee_type": tee_type,
        "qe_svn": qe_svn,
        "pce_svn": pce_svn,
        "qe_vendor_id": qe_vendor_id,
        "user_data": user_data,
        "td": td,
        "raw_header": raw_header,
        "raw_td_report": raw_td_report,
        "quote_signature": quote_sig,
        "attestation_pub_key": att_pub_key,
        "qe_report": qe_report,
        "qe_report_signature": qe_report_sig,
        "qe_auth_data": qe_auth_data,
        "cert_data_type": cert_data_type,
        "cert_data": cert_data,
    }


def _tdx_extract_pem_certs(pem_data: bytes) -> list:
    certs = []
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
        certs.append(load_pem_x509_certificate(pem_str[begin:end].encode("ascii")))
        start = end
    return certs


def _tdx_verify_cert_chain(certs: list) -> bool:
    for i in range(len(certs) - 1):
        child, parent = certs[i], certs[i + 1]
        try:
            parent.public_key().verify(
                child.signature, child.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
            )
        except Exception:
            return False
    if certs:
        root = certs[-1]
        try:
            root.public_key().verify(
                root.signature, root.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
            )
        except Exception:
            return False
    return True


def _tdx_extract_fmspc(cert) -> Optional[str]:
    try:
        for ext in cert.extensions:
            if ext.oid.dotted_string == "1.2.840.113741.1.13.1":
                raw = ext.value.value
                fmspc_oid = bytes.fromhex("060a2a864886f84d010d0104")
                idx = raw.find(fmspc_oid)
                if idx >= 0:
                    search_start = idx + len(fmspc_oid)
                    for j in range(search_start, min(search_start + 20, len(raw) - 6)):
                        if raw[j] == 0x04 and raw[j + 1] == 0x06:
                            return raw[j + 2:j + 8].hex()
    except Exception:
        pass
    return None


def _tdx_verify_ecdsa_p256(public_key_bytes: bytes, message: bytes, signature_bytes: bytes) -> bool:
    x = int.from_bytes(public_key_bytes[:32], "big")
    y = int.from_bytes(public_key_bytes[32:64], "big")
    pub_key = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1()).public_key()
    r = int.from_bytes(signature_bytes[:32], "big")
    s = int.from_bytes(signature_bytes[32:64], "big")
    der_sig = utils.encode_dss_signature(r, s)
    try:
        pub_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _tdx_fetch_tcb_status(fmspc: str, tee_tcb_svn: bytes) -> str:
    url = f"{_INTEL_PCS_BASE}/tcb?fmspc={fmspc}&type=TDX"
    resp = requests.get(url, timeout=15)
    if resp.status_code != 200:
        return f"PCS returned {resp.status_code}"
    tcb_info = resp.json()
    tcb_info = tcb_info.get("tcbInfo", tcb_info)
    for level in tcb_info.get("tcbLevels", []):
        tcb = level.get("tcb", {})
        tdx_components = tcb.get("tdxtcbcomponents", [])
        match = True
        for i, comp in enumerate(tdx_components):
            if i < len(tee_tcb_svn) and tee_tcb_svn[i] < comp.get("svn", 0):
                match = False
                break
        if match:
            status = level.get("tcbStatus", "Unknown")
            tcb_date = level.get("tcbDate", "")
            return f"{status} (as of {tcb_date})" if tcb_date else status
    return "OutOfDate (no matching TCB level found)"


def check_tdx_cpu_attestation(data: str) -> AttestationResult:
    """Verify an Intel TDX attestation quote.

    Args:
        data: Hex-encoded TDX quote (content of cpu_quote.txt).

    Returns:
        AttestationResult with verification status and parsed report fields.
    """
    errors = []
    checks = {}

    # Parse
    try:
        raw = bytes.fromhex(data.strip())
        q = _tdx_parse_quote(raw)
        checks["quote_parsed"] = True
    except Exception as e:
        return AttestationResult(
            valid=False, attestation_type="TDX",
            checks={"quote_parsed": False}, errors=[str(e)],
        )

    td = q["td"]

    # Extract certs
    if q["cert_data_type"] not in (5, 6):
        errors.append(f"Unsupported cert data type: {q['cert_data_type']}")
        checks["cert_chain_valid"] = False
    else:
        certs = _tdx_extract_pem_certs(q["cert_data"])
        if len(certs) < 2:
            errors.append(f"Expected at least 2 certificates, got {len(certs)}")
            checks["cert_chain_valid"] = False
        else:
            checks["cert_chain_valid"] = _tdx_verify_cert_chain(certs)
            if not checks["cert_chain_valid"]:
                errors.append("PCK certificate chain signature verification failed")

    # QE Report Signature
    if checks.get("cert_chain_valid"):
        pck_pub_key = certs[0].public_key()
        qe_sig = q["qe_report_signature"]
        r = int.from_bytes(qe_sig[:32], "big")
        s = int.from_bytes(qe_sig[32:64], "big")
        der_sig = utils.encode_dss_signature(r, s)
        try:
            pck_pub_key.verify(der_sig, q["qe_report"], ec.ECDSA(hashes.SHA256()))
            checks["qe_report_signature_valid"] = True
        except Exception:
            checks["qe_report_signature_valid"] = False
            errors.append("QE Report signature verification failed")

        # Attestation key binding
        att_key_hash = hashlib.sha256(
            q["attestation_pub_key"] + q["qe_auth_data"]
        ).digest()
        qe_report_data = q["qe_report"][320:384]
        checks["attestation_key_bound"] = qe_report_data[:32] == att_key_hash
        if not checks["attestation_key_bound"]:
            errors.append("Attestation key hash does not match QE Report REPORTDATA")

        # FMSPC
        fmspc = _tdx_extract_fmspc(certs[0])
    else:
        checks.setdefault("qe_report_signature_valid", False)
        checks["attestation_key_bound"] = False
        fmspc = None

    # Quote Signature
    signed_data = q["raw_header"] + q["raw_td_report"]
    checks["quote_signature_valid"] = _tdx_verify_ecdsa_p256(
        q["attestation_pub_key"], signed_data, q["quote_signature"]
    )
    if not checks["quote_signature_valid"]:
        errors.append("Quote signature verification failed")

    # TCB status (best-effort)
    tcb_status = "Unknown"
    if fmspc:
        try:
            tcb_status = _tdx_fetch_tcb_status(fmspc, td["tee_tcb_svn"])
        except Exception as e:
            tcb_status = f"Could not fetch: {e}"

    valid = all([
        checks.get("quote_parsed"),
        checks.get("cert_chain_valid"),
        checks.get("qe_report_signature_valid"),
        checks.get("attestation_key_bound"),
        checks.get("quote_signature_valid"),
    ])

    report = {
        "version": q["version"],
        "att_key_type": q["att_key_type"],
        "tee_type": q["tee_type"],
        "qe_svn": q["qe_svn"],
        "pce_svn": q["pce_svn"],
        "qe_vendor_id": q["qe_vendor_id"].hex(),
        "tee_tcb_svn": td["tee_tcb_svn"].hex(),
        "mr_seam": td["mr_seam"].hex(),
        "mr_td": td["mr_td"].hex(),
        "mr_config_id": td["mr_config_id"].hex(),
        "mr_owner": td["mr_owner"].hex(),
        "mr_owner_config": td["mr_owner_config"].hex(),
        "rt_mr0": td["rt_mr0"].hex(),
        "rt_mr1": td["rt_mr1"].hex(),
        "rt_mr2": td["rt_mr2"].hex(),
        "rt_mr3": td["rt_mr3"].hex(),
        "report_data": td["report_data"].hex(),
        "td_attributes": td["td_attributes"].hex(),
        "xfam": td["xfam"].hex(),
        "fmspc": fmspc or "",
        "tcb_status": tcb_status,
    }

    return AttestationResult(
        valid=valid, attestation_type="TDX",
        checks=checks, report=report, errors=errors,
    )


# ===========================================================================
#
#  AMD SEV-SNP
#
# ===========================================================================

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


def _amd_verify_chain_openssl(vcek_der: bytes, chain_pem: bytes) -> bool:
    with tempfile.TemporaryDirectory() as td:
        vcek_pem_path = Path(td) / "vcek.pem"
        r = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
            input=vcek_der, capture_output=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"openssl x509 convert failed: {r.stderr.decode()}")
        vcek_pem_path.write_bytes(r.stdout)

        pem_blocks = _amd_split_pem(chain_pem)
        if len(pem_blocks) < 2:
            raise RuntimeError(f"Expected at least 2 certs in chain, got {len(pem_blocks)}")

        ark_path = Path(td) / "ark.pem"
        ask_path = Path(td) / "ask.pem"
        ark_path.write_bytes(pem_blocks[1])
        ask_path.write_bytes(pem_blocks[0])

        r = subprocess.run(
            ["openssl", "verify", "-CAfile", str(ark_path),
             "-untrusted", str(ask_path), str(vcek_pem_path)],
            capture_output=True,
        )
        return r.returncode == 0


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


def check_amd_cpu_attestation(data: str, product: str = "") -> AttestationResult:
    """Verify an AMD SEV-SNP attestation report.

    Args:
        data: Base64-encoded attestation report (content of amd_cpu_quote.txt).
        product: AMD product name (Genoa, Milan, Turin). Auto-detected if empty.

    Returns:
        AttestationResult with verification status and parsed report fields.
    """
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
        checks["cert_chain_valid"] = _amd_verify_chain_openssl(vcek_der, chain_pem)
        if not checks["cert_chain_valid"]:
            errors.append("Certificate chain verification failed (VCEK → ASK → ARK)")
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


# ===========================================================================
#
#  CPU (auto-detect TDX vs SEV-SNP)
#
# ===========================================================================


def _detect_cpu_quote_type(data: str) -> str:
    """Detect whether the quote is Intel TDX (hex) or AMD SEV-SNP (base64).

    Returns "TDX", "SEV-SNP", or "unknown".
    """
    text = data.strip()

    # Try hex decode — TDX quotes are hex-encoded with version=4, tee_type=0x81
    try:
        raw = bytes.fromhex(text)
        if len(raw) >= 8:
            version, _, tee_type = struct.unpack_from("<HHI", raw, 0)
            if version == 4 and tee_type == 0x81:
                return "TDX"
    except ValueError:
        pass

    # Try base64 decode — AMD SEV-SNP reports have version >= 2 and sig_algo == 1
    try:
        raw = base64.b64decode(text)
        if len(raw) >= 0x038:
            version = struct.unpack_from("<I", raw, 0)[0]
            sig_algo = struct.unpack_from("<I", raw, 0x034)[0]
            if version in (2, 3, 4) and sig_algo == 1:
                return "SEV-SNP"
    except Exception:
        pass

    return "unknown"


def check_cpu_attestation(data: str, product: str = "") -> AttestationResult:
    """Verify a CPU attestation quote, auto-detecting Intel TDX vs AMD SEV-SNP.

    Args:
        data: The raw quote text (hex-encoded TDX or base64-encoded SEV-SNP).
        product: AMD product name (only used if quote is SEV-SNP). Auto-detected if empty.

    Returns:
        AttestationResult with verification status and parsed report fields.
    """
    quote_type = _detect_cpu_quote_type(data)

    if quote_type == "TDX":
        return check_tdx_cpu_attestation(data)
    elif quote_type == "SEV-SNP":
        return check_amd_cpu_attestation(data, product=product)
    else:
        return AttestationResult(
            valid=False,
            attestation_type="unknown",
            errors=["Could not detect quote type (expected hex-encoded TDX or base64-encoded SEV-SNP)"],
        )


# ===========================================================================
#
#  NVIDIA GPU
#
# ===========================================================================

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


def check_nvidia_gpu_attestation(data: str) -> AttestationResult:
    """Verify NVIDIA GPU attestation via the NVIDIA Remote Attestation Service.

    Args:
        data: JSON attestation payload (content of gpu_attest.txt).

    Returns:
        AttestationResult with verification status and parsed attestation claims.
    """
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


# ===========================================================================
#
#  SECRET VM (end-to-end: CPU + GPU + binding checks)
#
# ===========================================================================

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


def check_secret_vm(url: str, product: str = "") -> AttestationResult:
    """Verify a Secret VM by fetching CPU and GPU attestation from its endpoints.

    Connects to the VM's attestation service at <url>:29343, fetches the CPU
    quote from /cpu and (optionally) the GPU quote from /gpu, verifies both,
    and checks the binding between:
      - The TLS certificate fingerprint and the first half of report_data
      - The GPU nonce and the second half of report_data (if GPU is present)

    Args:
        url: VM address (e.g. "https://host:29343", "host:29343", or just "host").
        product: AMD product name (only used for SEV-SNP). Auto-detected if empty.

    Returns:
        AttestationResult with attestation_type="SECRET-VM".
    """
    errors = []
    checks = {}
    report = {}

    host, port = _parse_vm_url(url)
    base_url = f"https://{host}:{port}"

    # 1. Get TLS certificate fingerprint
    try:
        tls_fingerprint = _get_tls_cert_fingerprint(host, port)
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
        resp = requests.get(f"{base_url}/cpu", timeout=15, verify=True)
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

    cpu_result = check_cpu_attestation(cpu_data, product=product)
    checks["cpu_attestation_valid"] = cpu_result.valid
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
        resp = requests.get(f"{base_url}/gpu", timeout=15, verify=True)
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
        gpu_result = check_nvidia_gpu_attestation(gpu_data)
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

    # Overall validity
    required_checks = [
        checks.get("tls_cert_obtained"),
        checks.get("cpu_quote_fetched"),
        checks.get("cpu_attestation_valid"),
        checks.get("tls_binding"),
    ]
    if gpu_present:
        required_checks.append(checks.get("gpu_attestation_valid"))
        required_checks.append(checks.get("gpu_binding"))

    valid = all(required_checks)

    return AttestationResult(
        valid=valid, attestation_type="SECRET-VM",
        checks=checks, report=report, errors=errors,
    )


# ===========================================================================
#
#  SECRETVM WORKLOAD VERIFICATION
#
# ===========================================================================

import csv
import yaml as _yaml


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class WorkloadResult:
    """Result of a SecretVM workload verification."""
    status: str  # "authentic_match" | "authentic_mismatch" | "not_authentic"
    template_name: Optional[str] = None
    vm_type: Optional[str] = None
    artifacts_ver: Optional[str] = None
    env: Optional[str] = None


# ---------------------------------------------------------------------------
# RTMR replay
# ---------------------------------------------------------------------------

def _replay_rtmr(history: list) -> str:
    """SHA-384 RTMR accumulator — mirrors portal's replayRTMR logic."""
    if not history:
        return "00" * 48

    mr = bytearray(48)
    for entry in history:
        entry_bytes = bytes.fromhex(entry)
        if len(entry_bytes) < 48:
            entry_bytes = entry_bytes + bytes(48 - len(entry_bytes))
        combined = bytes(mr) + entry_bytes
        digest = hashlib.sha384(combined).digest()
        mr = bytearray(digest[:48])

    return bytes(mr).hex()


def _calculate_rtmr3(docker_compose: str | bytes, rootfs_data: str) -> str:
    """Calculate expected RTMR3 from docker-compose content and rootfs_data.

    Hashes the raw file bytes directly (no YAML normalization), matching
    the portal's Buffer path in calculateRTMR3.
    """
    compose_bytes = docker_compose if isinstance(docker_compose, bytes) else docker_compose.encode("utf-8")
    sha256_hex = hashlib.sha256(compose_bytes).hexdigest()
    rootfs_hex = rootfs_data.lower().lstrip("0x")
    return _replay_rtmr([sha256_hex, rootfs_hex])


# ---------------------------------------------------------------------------
# Registry loader
# ---------------------------------------------------------------------------

_tdx_registry_cache: Optional[list] = None


def _load_tdx_registry() -> list:
    global _tdx_registry_cache
    if _tdx_registry_cache is not None:
        return _tdx_registry_cache

    csv_path = Path(__file__).parents[4] / "artifacts_registry" / "tdx.csv"
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({k: v.strip().lower() for k, v in row.items()})
    _tdx_registry_cache = rows
    return rows


def _find_matching_artifacts(mrtd: str, rtmr0: str, rtmr1: str, rtmr2: str) -> list:
    m = mrtd.lower().lstrip("0x")
    r0 = rtmr0.lower().lstrip("0x")
    r1 = rtmr1.lower().lstrip("0x")
    r2 = rtmr2.lower().lstrip("0x")
    return [
        e for e in _load_tdx_registry()
        if e["mrtd"] == m and e["rtmr0"] == r0 and e["rtmr1"] == r1 and e["rtmr2"] == r2
    ]


def _parse_semver(ver: str):
    """Return (major, minor, patch, pre) tuple for sorting."""
    clean = ver.lstrip("v")
    dash = clean.find("-")
    if dash >= 0:
        core, pre = clean[:dash], clean[dash + 1:]
    else:
        core, pre = clean, ""
    parts = core.split(".")
    try:
        major, minor, patch = int(parts[0] or 0), int(parts[1] if len(parts) > 1 else 0), int(parts[2] if len(parts) > 2 else 0)
    except ValueError:
        major, minor, patch = 0, 0, 0
    return major, minor, patch, pre


def _pick_newest_version(entries: list) -> Optional[dict]:
    if not entries:
        return None

    def sort_key(e):
        major, minor, patch, pre = _parse_semver(e.get("artifacts_ver", ""))
        # release ("") beats pre-release; negate numeric parts for descending sort
        return (-major, -minor, -patch, 0 if pre == "" else 1, pre)

    return sorted(entries, key=sort_key)[0]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_secretvm_version(data: str) -> Optional[dict]:
    """Given a TDX quote (hex string), return matching SecretVM version info.

    Returns a dict with ``template_name`` and ``artifacts_ver``, or ``None``
    when the quote is not from a known SecretVM.
    """
    try:
        raw = bytes.fromhex(data.strip())
        q = _tdx_parse_quote(raw)
        td = q["td"]
        mrtd = td["mr_td"].hex()
        rtmr0 = td["rt_mr0"].hex()
        rtmr1 = td["rt_mr1"].hex()
        rtmr2 = td["rt_mr2"].hex()
    except Exception:
        return None

    matches = _find_matching_artifacts(mrtd, rtmr0, rtmr1, rtmr2)
    best = _pick_newest_version(matches)
    if best is None:
        return None
    return {
        "template_name": best["template_name"],
        "artifacts_ver": best["artifacts_ver"],
    }


def verify_tdx_workload(data: str, docker_compose_yaml: str) -> WorkloadResult:
    """Verify that a TDX quote was produced by a known SecretVM running the
    given docker-compose YAML.

    Args:
        data: Hex-encoded TDX quote.
        docker_compose_yaml: Contents of the docker-compose.yaml file.

    Returns:
        WorkloadResult with status "authentic_match", "authentic_mismatch", or
        "not_authentic".
    """
    try:
        raw = bytes.fromhex(data.strip())
        q = _tdx_parse_quote(raw)
        td = q["td"]
        mrtd = td["mr_td"].hex()
        rtmr0 = td["rt_mr0"].hex()
        rtmr1 = td["rt_mr1"].hex()
        rtmr2 = td["rt_mr2"].hex()
        quote_rtmr3 = td["rt_mr3"].hex()
    except Exception:
        return WorkloadResult(status="not_authentic")

    candidates = _find_matching_artifacts(mrtd, rtmr0, rtmr1, rtmr2)
    if not candidates:
        return WorkloadResult(status="not_authentic")

    best = _pick_newest_version(candidates)
    template_name = best["template_name"]
    vm_type = best["vm_type"]
    artifacts_ver = best["artifacts_ver"]
    # vm_type column in CSV contains the environment (prod/dev)
    env = vm_type

    for entry in candidates:
        expected = _calculate_rtmr3(docker_compose_yaml, entry["rootfs_data"])
        if expected == quote_rtmr3:
            return WorkloadResult(
                status="authentic_match",
                template_name=entry["template_name"],
                vm_type=entry["vm_type"],
                artifacts_ver=entry["artifacts_ver"],
                env=entry["vm_type"],
            )

    return WorkloadResult(
        status="authentic_mismatch",
        template_name=template_name,
        vm_type=vm_type,
        artifacts_ver=artifacts_ver,
        env=env,
    )


def format_workload_result(r: WorkloadResult) -> str:
    """Human-readable string for a WorkloadResult."""
    if r.status == "not_authentic":
        return "\U0001f6ab Attestation doesn't belong to an authentic SecretVM"

    vm_line = (
        f"\u2705 Confirmed an authentic SecretVM (TDX), "
        f"vm_type {r.template_name}, artifacts {r.artifacts_ver}, environment {r.env}"
    )
    if r.status == "authentic_match":
        return vm_line + "\n\u2705 Confirmed that the VM is running the specified docker-compose.yaml"

    return vm_line + "\n\U0001f6ab Attestation does not match the specified docker-compose.yaml"


# ---------------------------------------------------------------------------
# SEV-SNP workload verification (TODO)
# ---------------------------------------------------------------------------


def verify_sev_workload(data: str, docker_compose_yaml: str) -> WorkloadResult:
    """Verify an AMD SEV-SNP workload against a docker-compose.yaml.

    TODO: SEV-SNP workload verification is not yet implemented.  Always returns
    ``not_authentic`` until a SEV artifact registry and measurement replay logic
    (equivalent to TDX RTMR3 replay) are added.
    """
    return WorkloadResult(status="not_authentic")


# ---------------------------------------------------------------------------
# Generic workload verifier (auto-detects TDX vs SEV-SNP)
# ---------------------------------------------------------------------------


def verify_workload(data: str, docker_compose_yaml: str) -> WorkloadResult:
    """Verify that a CPU quote was produced by a known SecretVM running the
    given docker-compose YAML.

    Automatically detects whether *data* is an Intel TDX (hex) or AMD SEV-SNP
    (base64) quote and delegates to the appropriate lower-level function:

    - TDX  → :func:`verify_tdx_workload`
    - SEV-SNP → :func:`verify_sev_workload` (TODO – currently returns not_authentic)
    - unknown → returns ``not_authentic``

    Args:
        data: Hex-encoded TDX quote **or** base64-encoded SEV-SNP report.
        docker_compose_yaml: Contents of the docker-compose.yaml file.

    Returns:
        :class:`WorkloadResult` with status ``"authentic_match"``,
        ``"authentic_mismatch"``, or ``"not_authentic"``.
    """
    quote_type = _detect_cpu_quote_type(data)
    if quote_type == "TDX":
        return verify_tdx_workload(data, docker_compose_yaml)
    if quote_type == "SEV-SNP":
        return verify_sev_workload(data, docker_compose_yaml)
    return WorkloadResult(status="not_authentic")
