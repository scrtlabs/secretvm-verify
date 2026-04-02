"""Intel TDX attestation verification."""

import hashlib
import struct
from typing import Optional

import requests
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate

from .types import AttestationResult

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


def check_tdx_cpu_attestation(data_or_url: str) -> AttestationResult:
    """Verify an Intel TDX attestation quote.

    Args:
        data_or_url: Hex-encoded TDX quote, or a VM URL to fetch the quote from.

    Returns:
        AttestationResult with verification status and parsed report fields.
    """
    from .url import is_vm_url, fetch_cpu_quote
    data = fetch_cpu_quote(data_or_url) if is_vm_url(data_or_url) else data_or_url
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
