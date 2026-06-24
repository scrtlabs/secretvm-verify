"""Proof-of-Cloud verification against the trust-server peer network.

The verdict is produced by failing over across the community-vetted
trust-server peers (https://github.com/proofofcloud/trust-server). Each peer
exposes ``POST /check_quote`` taking a hex-encoded quote and returning
``{whitelisted, machine_id, revoked?, revoked_at?}``. Peers are tried in list
order; the first usable answer wins. The peer list ships bundled and is
best-effort refreshed from GitHub once per process.
"""

import asyncio
import base64
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

import requests

from .cpu import _detect_cpu_quote_type
from .types import AttestationResult, order_checks

# Raw GitHub URL for the published peers list.
_PEERS_GITHUB_RAW = (
    "https://raw.githubusercontent.com/proofofcloud/trust-server/main/"
    "public_info/peers_list.txt"
)

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Module-level memoization of the resolved peer list (per process).
_peers_cache: Optional[list] = None


# ---------------------------------------------------------------------------
# Quote -> hex encoding
# ---------------------------------------------------------------------------

def to_hex_quote(cpu_data: str) -> str:
    """Return the canonical lowercase-hex encoding of a CPU quote.

    Reuses the existing TDX/SEV-SNP detection, then strictly validates the
    *whole* trimmed string before returning (the detectors only sniff header
    bytes, and ``bytes.fromhex`` / base64 decode can silently accept partially
    malformed input).

    - TDX (hex): the entire trimmed string must match ``^[0-9a-fA-F]+$`` with
      even length; the result is lowercased.
    - SEV-SNP (base64): strict base64 decode of the whole string, re-encoded as
      lowercase hex.

    Raises:
        ValueError: if the input matches neither a valid hex nor a valid base64
            quote (no network call should be made by the caller in that case).
    """
    text = cpu_data.strip()
    quote_type = _detect_cpu_quote_type(text)

    if quote_type == "TDX":
        if len(text) % 2 != 0 or not _HEX_RE.match(text):
            raise ValueError(
                "Could not encode quote for trust-server (unrecognized quote format)"
            )
        return text.lower()

    if quote_type == "SEV-SNP":
        # Strip internal whitespace first (a VM may serve line-wrapped base64),
        # matching the Node SDK and the main SEV path in amd.py, then strict-decode.
        compact = re.sub(r"\s+", "", text)
        try:
            raw = base64.b64decode(compact, validate=True)
        except Exception:
            raise ValueError(
                "Could not encode quote for trust-server (unrecognized quote format)"
            )
        return raw.hex()

    raise ValueError(
        "Could not encode quote for trust-server (unrecognized quote format)"
    )


# ---------------------------------------------------------------------------
# Peer list loader + refresher
# ---------------------------------------------------------------------------

def _parse_peers(text: str) -> list:
    """Parse peer-list text into a list of https origins.

    Split on newlines; trim each line; skip blanks and ``#`` comments. Parse
    each remaining line as a URL, keep only ``https`` scheme, and reduce to its
    origin (``scheme://netloc``). Invalid or non-https lines are dropped
    individually.
    """
    peers: list = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parsed = urllib.parse.urlparse(line)
        except Exception:
            continue
        if parsed.scheme != "https" or not parsed.netloc:
            continue
        origin = f"{parsed.scheme}://{parsed.netloc}"
        peers.append(origin)
    return peers


def load_bundled_peers() -> list:
    """Read and parse the bundled peers file (offline fallback)."""
    path = Path(__file__).parent / "data" / "trust_server_peers.txt"
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return []
    return _parse_peers(text)


def refresh_peers_from_github() -> Optional[list]:
    """Fetch the published peers list from GitHub (5s timeout, best-effort).

    Returns the parsed peer list if it yields >=1 valid peer, else ``None``.
    Best-effort persists the fetched raw text to the bundled file (write errors
    ignored). Never raises.
    """
    try:
        with urllib.request.urlopen(_PEERS_GITHUB_RAW, timeout=5) as resp:
            text = resp.read().decode("utf-8")
    except Exception:
        return None

    peers = _parse_peers(text)
    if not peers:
        return None

    # Best-effort persist so a future offline process starts from the newer list.
    try:
        path = Path(__file__).parent / "data" / "trust_server_peers.txt"
        path.write_text(text, encoding="utf-8")
    except Exception:
        pass

    return peers


def _resolve_peers() -> list:
    """Module-memoized peer resolution.

    On first call, attempt one GitHub refresh; if it yields >=1 valid peer use
    it, else fall back to the bundled file. The result is cached for the rest of
    the process.
    """
    global _peers_cache
    if _peers_cache is not None:
        return _peers_cache

    refreshed = refresh_peers_from_github()
    if refreshed:
        _peers_cache = refreshed
    else:
        _peers_cache = load_bundled_peers()
    return _peers_cache


def _reset_peers_cache() -> None:
    """Clear the memoized peer list (for tests)."""
    global _peers_cache
    _peers_cache = None


# ---------------------------------------------------------------------------
# Single-peer query
# ---------------------------------------------------------------------------

def _query_peer(origin: str, hex_quote: str):
    """Query a single peer's ``/check_quote`` endpoint.

    Returns a dict ``{whitelisted, machine_id, revoked, revoked_at}`` on a
    usable answer, or a failure-reason string otherwise.
    """
    try:
        resp = requests.post(
            f"{origin}/check_quote",
            json={"quote": hex_quote},
            timeout=10,
        )
    except Exception as e:
        return f"{origin}: request failed: {e}"

    if resp.status_code != 200:
        return f"{origin}: HTTP {resp.status_code}"

    try:
        body = resp.json()
    except Exception:
        return f"{origin}: response was not valid JSON"

    if not isinstance(body, dict):
        return f"{origin}: response was not a JSON object"

    whitelisted = body.get("whitelisted")
    machine_id = body.get("machine_id")
    if not isinstance(whitelisted, bool):
        return f"{origin}: 'whitelisted' missing or not a boolean"
    if not isinstance(machine_id, str) or not machine_id:
        return f"{origin}: 'machine_id' missing or not a non-empty string"

    revoked_raw = body.get("revoked")
    if revoked_raw is not None and not isinstance(revoked_raw, bool):
        return f"{origin}: 'revoked' present but not a boolean"
    revoked = bool(revoked_raw)

    revoked_at = None
    if revoked:
        ra = body.get("revoked_at")
        revoked_at = ra if isinstance(ra, str) else None

    return {
        "whitelisted": whitelisted,
        "machine_id": machine_id,
        "revoked": revoked,
        "revoked_at": revoked_at,
    }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def check_proof_of_cloud(cpu_data: str) -> AttestationResult:
    """Verify a CPU quote against the trust-server peer network.

    Encodes the quote to hex, resolves the peer list, then queries peers in
    order until the first usable answer. Passes iff that answer is
    ``whitelisted`` and not ``revoked``.

    Args:
        cpu_data: Raw CPU quote text as served by the VM's /cpu endpoint
            (hex for TDX, base64 for SEV-SNP).

    Returns:
        AttestationResult with attestation_type="PROOF-OF-CLOUD". The single
        check ``proof_of_cloud_verified`` reflects the verdict. ``report
        ["proof_of_cloud"]`` is always populated.
    """
    checks: dict = {}
    errors: list = []

    def _result(valid: bool, *, whitelisted=False, machine_id=None, revoked=False,
                revoked_at=None, trust_server=None, peers_tried=None) -> AttestationResult:
        checks["proof_of_cloud_verified"] = valid
        report = {
            "proof_of_cloud": {
                "whitelisted": whitelisted,
                "machine_id": machine_id,
                "revoked": revoked,
                "revoked_at": revoked_at,
                "trust_server": trust_server,
                "peers_tried": peers_tried if peers_tried is not None else [],
            }
        }
        return AttestationResult(
            valid=valid, attestation_type="PROOF-OF-CLOUD",
            checks=order_checks(checks), report=report, errors=errors,
        )

    # 1. Encode the quote to canonical hex. Encode failure => no network call.
    try:
        hex_quote = to_hex_quote(cpu_data)
    except ValueError as e:
        errors.append(str(e))
        return _result(False, peers_tried=[])

    # 2. Resolve the peer list.
    peers = _resolve_peers()
    if not peers:
        errors.append("No trust-server peers available")
        return _result(False, peers_tried=[])

    # 3. Failover: try peers in order, first usable answer wins. Per-peer
    # transport/parse failures are collected separately and only surfaced if no
    # peer returns a usable answer (a definitive verdict from a later peer must
    # not carry earlier peers' failure noise).
    peers_tried: list = []
    reasons: list = []
    for origin in peers:
        peers_tried.append(origin)
        answer = _query_peer(origin, hex_quote)
        if isinstance(answer, str):
            reasons.append(answer)
            continue

        machine_id = answer["machine_id"]
        whitelisted = answer["whitelisted"]
        revoked = answer["revoked"]
        revoked_at = answer["revoked_at"]

        if revoked:
            when = revoked_at if revoked_at else "an unknown date"
            errors.append(f"Machine {machine_id} was revoked on {when}")
            return _result(
                False, whitelisted=False, machine_id=machine_id, revoked=True,
                revoked_at=revoked_at, trust_server=origin, peers_tried=peers_tried,
            )

        if not whitelisted:
            errors.append(
                f"Machine {machine_id} is not whitelisted by trust-server peer {origin}"
            )
            return _result(
                False, whitelisted=False, machine_id=machine_id, revoked=False,
                revoked_at=None, trust_server=origin, peers_tried=peers_tried,
            )

        # Pass.
        return _result(
            True, whitelisted=True, machine_id=machine_id, revoked=False,
            revoked_at=None, trust_server=origin, peers_tried=peers_tried,
        )

    # 4. No peer returned a usable answer — surface every peer's failure reason.
    errors.extend(reasons)
    return _result(False, peers_tried=peers_tried)


async def check_proof_of_cloud_async(cpu_data: str) -> AttestationResult:
    """Async variant of check_proof_of_cloud (offloads the blocking path)."""
    return await asyncio.to_thread(check_proof_of_cloud, cpu_data)
