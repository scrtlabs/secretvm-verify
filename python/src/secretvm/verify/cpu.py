"""CPU attestation auto-detection (Intel TDX vs AMD SEV-SNP)."""

import asyncio
import base64
import struct

from .types import AttestationResult
from .tdx import check_tdx_cpu_attestation, check_tdx_cpu_attestation_async
from .amd import check_sev_cpu_attestation, check_sev_cpu_attestation_async


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


def check_cpu_attestation(data_or_url: str, product: str = "") -> AttestationResult:
    """Verify a CPU attestation quote, auto-detecting Intel TDX vs AMD SEV-SNP.

    Args:
        data_or_url: Raw quote text (hex TDX or base64 SEV-SNP), or a VM URL to fetch from.
        product: AMD product name (only used if quote is SEV-SNP). Auto-detected if empty.

    Returns:
        AttestationResult with verification status and parsed report fields.
    """
    from .url import is_vm_url, fetch_cpu_quote
    data = fetch_cpu_quote(data_or_url) if is_vm_url(data_or_url) else data_or_url
    quote_type = _detect_cpu_quote_type(data)

    if quote_type == "TDX":
        return check_tdx_cpu_attestation(data)
    elif quote_type == "SEV-SNP":
        return check_sev_cpu_attestation(data, product=product)
    else:
        return AttestationResult(
            valid=False,
            attestation_type="unknown",
            errors=["Could not detect quote type (expected hex-encoded TDX or base64-encoded SEV-SNP)"],
        )


async def check_cpu_attestation_async(
    data_or_url: str, product: str = ""
) -> AttestationResult:
    """Async variant of :func:`check_cpu_attestation`.

    Auto-detects TDX vs SEV-SNP, then dispatches to the appropriate async
    verifier. The TDX path uses dcap-qvl's native async collateral fetching;
    the SEV-SNP path runs in a thread pool (via
    :func:`check_sev_cpu_attestation_async`) since SEV verification has no
    async-native operations to bridge.

    Use this from inside an event loop (FastAPI handlers, Jupyter notebooks,
    other async frameworks).
    """
    from .url import is_vm_url, fetch_cpu_quote
    if is_vm_url(data_or_url):
        # fetch_cpu_quote is sync (requests-based) — offload to a thread.
        data = await asyncio.to_thread(fetch_cpu_quote, data_or_url)
    else:
        data = data_or_url
    quote_type = _detect_cpu_quote_type(data)

    if quote_type == "TDX":
        return await check_tdx_cpu_attestation_async(data)
    elif quote_type == "SEV-SNP":
        return await check_sev_cpu_attestation_async(data, product=product)
    else:
        return AttestationResult(
            valid=False,
            attestation_type="unknown",
            errors=["Could not detect quote type (expected hex-encoded TDX or base64-encoded SEV-SNP)"],
        )
