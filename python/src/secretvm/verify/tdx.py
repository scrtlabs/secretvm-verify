"""Intel TDX attestation verification.

Cryptographic verification (PCK chain, QE Identity, CRLs, TCB Info signature,
quote signature) is delegated to the upstream `dcap-qvl` library, which
implements the full Intel DCAP quote verification flow. This module's job is
to parse the quote so we can populate report fields (mr_td, report_data,
fmspc, etc.), then hand off to dcap-qvl for the actual verification.
"""

import asyncio
import os
import struct
import time
from typing import Optional

import dcap_qvl
from cryptography.x509 import load_pem_x509_certificate

from .types import AttestationResult

# Override via the SECRETVM_PCCS_URL env var (e.g. self-hosted PCCS, or
# https://api.trustedservices.intel.com for Intel's PCS directly).
_PCCS_HOST = (os.environ.get("SECRETVM_PCCS_URL") or "https://pccs.scrtlabs.com").strip() or "https://pccs.scrtlabs.com"


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

    # TD Report Body: 584 bytes at offset 48
    off = 48
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
    off += 4 + 64 + 64  # skip quote_sig (64) + att_pub_key (64)

    outer_cert_type = struct.unpack_from("<H", raw, off)[0]; off += 2
    outer_cert_size = struct.unpack_from("<I", raw, off)[0]; off += 4
    outer_cert_data = raw[off:off + outer_cert_size]

    if outer_cert_type == 6:
        coff = 384 + 64  # skip qe_report (384) + qe_report_sig (64)
        qe_auth_len = struct.unpack_from("<H", outer_cert_data, coff)[0]; coff += 2
        coff += qe_auth_len  # skip qe_auth_data
        cert_data_type = struct.unpack_from("<H", outer_cert_data, coff)[0]; coff += 2
        cert_data_len = struct.unpack_from("<I", outer_cert_data, coff)[0]; coff += 4
        cert_data = outer_cert_data[coff:coff + cert_data_len]
    else:
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


def _tdx_extract_fmspc(cert) -> Optional[str]:
    """Extract the 6-byte FMSPC from the PCK leaf certificate's Intel SGX extension."""
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


def _maybe_dehex(b: bytes) -> bytes:
    """Decode hex-ASCII to raw bytes if `b` looks like hex-encoded ASN.1.

    The SCRT PCCS deployment returns the root CA CRL as hex-encoded ASCII
    (e.g. b'30820122...') instead of raw DER. dcap-qvl reads the body as raw
    bytes and chokes with TrailingData. We patch by detecting hex-ASCII and
    decoding it. Other PCCS deployments return raw DER, in which case the
    decode either fails or doesn't begin with an ASN.1 SEQUENCE tag, and we
    pass the bytes through unchanged.
    """
    try:
        decoded = bytes.fromhex(b.decode("ascii"))
        if decoded and decoded[0] == 0x30:  # ASN.1 SEQUENCE
            return decoded
    except (UnicodeDecodeError, ValueError):
        pass
    return b


async def _tdx_fetch_collateral(raw_quote: bytes) -> "dcap_qvl.QuoteCollateralV3":
    """Fetch the full DCAP collateral bundle from PCCS for a given quote.

    dcap-qvl parses the quote internally to extract the FMSPC and CA, then
    fetches all nine collateral fields (TCB Info, QE Identity, PCK CRL, Root
    CA CRL, plus their issuer chains and signatures).
    """
    coll = await dcap_qvl.get_collateral(_PCCS_HOST, raw_quote)
    # SCRT PCCS-specific patch: rebuild the collateral with a dehex'd root_ca_crl.
    return dcap_qvl.QuoteCollateralV3(
        pck_crl_issuer_chain=coll.pck_crl_issuer_chain,
        root_ca_crl=_maybe_dehex(coll.root_ca_crl),
        pck_crl=coll.pck_crl,
        tcb_info_issuer_chain=coll.tcb_info_issuer_chain,
        tcb_info=coll.tcb_info,
        tcb_info_signature=coll.tcb_info_signature,
        qe_identity_issuer_chain=coll.qe_identity_issuer_chain,
        qe_identity=coll.qe_identity,
        qe_identity_signature=coll.qe_identity_signature,
    )


async def _tdx_dcap_verify_async(raw_quote: bytes) -> "dcap_qvl.VerifiedReport":
    """Fetch collateral and verify a quote via dcap-qvl. Pure async — safe inside event loops."""
    collateral = await _tdx_fetch_collateral(raw_quote)
    return dcap_qvl.verify(raw_quote, collateral, int(time.time()))


async def check_tdx_cpu_attestation_async(data_or_url: str) -> AttestationResult:
    """Async variant of :func:`check_tdx_cpu_attestation`.

    Use this from inside an event loop (FastAPI handlers, Jupyter notebooks,
    other async frameworks). The sync :func:`check_tdx_cpu_attestation` is a
    thin ``asyncio.run()`` wrapper around this and cannot be called from a
    running loop.

    All blocking I/O (HTTP fetches for the VM quote and PCCS collateral) is
    properly offloaded so the event loop is never blocked for more than a
    syscall's worth of work.
    """
    from .url import is_vm_url, fetch_cpu_quote
    if is_vm_url(data_or_url):
        # fetch_cpu_quote is sync (requests-based) — offload to a thread so
        # the event loop isn't blocked on the network round-trip.
        data = await asyncio.to_thread(fetch_cpu_quote, data_or_url)
    else:
        data = data_or_url
    errors: list = []
    checks: dict = {}

    # Parse — needed to populate report fields and extract fmspc for the report
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

    # Best-effort fmspc extraction for the report — failure is non-fatal.
    fmspc: Optional[str] = None
    if q["cert_data_type"] in (5, 6):
        try:
            certs = _tdx_extract_pem_certs(q["cert_data"])
            if certs:
                fmspc = _tdx_extract_fmspc(certs[0])
        except Exception:
            pass

    # Full DCAP verification via dcap-qvl
    tcb_status = "Unknown"
    advisory_ids: list = []
    try:
        result = await _tdx_dcap_verify_async(raw)
        checks["quote_verified"] = True
        tcb_status = result.status
        advisory_ids = list(result.advisory_ids or [])
    except Exception as e:
        checks["quote_verified"] = False
        errors.append(f"Quote verification failed: {e}")

    # Policy: TDX must not be running in debug mode (would expose secrets).
    # Bit 0 of td_attributes[0] is the DEBUG flag (TUD = TD-Under-Debug).
    # dcap-qvl already rejects debug-mode quotes inside verify(); this
    # mirrors the SEV-SNP debug_disabled check for symmetry.
    checks["debug_disabled"] = (td["td_attributes"][0] & 0x01) == 0
    if not checks["debug_disabled"]:
        errors.append("TDX td_attributes has DEBUG bit set (debug-mode VM is not trusted)")

    valid = bool(
        checks.get("quote_parsed")
        and checks.get("quote_verified")
        and checks.get("debug_disabled")
    )

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
        "advisory_ids": advisory_ids,
    }

    return AttestationResult(
        valid=valid, attestation_type="TDX",
        checks=checks, report=report, errors=errors,
    )


def check_tdx_cpu_attestation(data_or_url: str) -> AttestationResult:
    """Verify an Intel TDX attestation quote (sync).

    Cryptographic verification is delegated to dcap-qvl, which performs the
    full DCAP flow: PCK certificate chain validation against the pinned Intel
    SGX Root CA, QE Identity check, PCK and Root CA CRL revocation checks,
    TCB Info signature verification, quote signature verification, and TCB
    status derivation.

    This function calls :func:`asyncio.run` internally and therefore cannot
    be invoked from inside an existing event loop. From async code (FastAPI,
    Jupyter, etc.), use :func:`check_tdx_cpu_attestation_async` instead.

    Args:
        data_or_url: Hex-encoded TDX quote, or a VM URL to fetch the quote from.

    Returns:
        AttestationResult with verification status and parsed report fields.
    """
    return asyncio.run(check_tdx_cpu_attestation_async(data_or_url))
