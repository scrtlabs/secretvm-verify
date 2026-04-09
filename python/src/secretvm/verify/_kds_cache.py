"""On-disk cache for AMD KDS responses (VCEK, cert chain, CRL).

The cache lives at ``~/.cache/secretvm-verify/amd/`` by default. Each cached
entry is two files: the payload, and a sidecar ``<key>.expires`` containing
the Unix-epoch expiration time as a string. Reads check the sidecar and
return the payload only if it's still fresh; misses fall through to the
network. The :func:`get_stale` helper returns the payload regardless of
freshness, used as a fallback when the network is unreachable.

The cache is on by default for the AMD SEV-SNP verifier in
``check_sev_cpu_attestation`` to minimize calls to ``kdsintf.amd.com`` and
avoid the rate-limit (HTTP 429) failures that the unauthenticated KDS
endpoint imposes when called repeatedly.
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Optional, Tuple


def _cache_root() -> Path:
    base = os.environ.get("SECRETVM_VERIFY_CACHE_DIR")
    if base:
        return Path(base) / "amd"
    return Path.home() / ".cache" / "secretvm-verify" / "amd"


def _key_paths(category: str, key: str) -> Tuple[Path, Path]:
    """Return the (payload, expires-sidecar) paths for a given cache key."""
    cache_dir = _cache_root() / category
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in key)
    if len(safe) > 200:
        safe = hashlib.sha256(key.encode()).hexdigest()
    return cache_dir / safe, cache_dir / (safe + ".expires")


def get(category: str, key: str) -> Optional[bytes]:
    """Return cached bytes if the entry exists and is still fresh, else None."""
    payload_path, expires_path = _key_paths(category, key)
    if not payload_path.exists() or not expires_path.exists():
        return None
    try:
        expires_at = float(expires_path.read_text().strip())
        if expires_at < time.time():
            return None
        return payload_path.read_bytes()
    except (OSError, ValueError):
        return None


def get_stale(category: str, key: str) -> Optional[bytes]:
    """Return cached bytes regardless of freshness, or None if missing.

    Used as a fallback when the network is unreachable: a stale CRL is
    better than no CRL at all, since the alternative is failing every
    verification while AMD KDS is down.
    """
    payload_path, _ = _key_paths(category, key)
    if not payload_path.exists():
        return None
    try:
        return payload_path.read_bytes()
    except OSError:
        return None


def put(category: str, key: str, data: bytes, ttl_seconds: int) -> None:
    """Atomically write a payload + expiration sidecar to disk."""
    payload_path, expires_path = _key_paths(category, key)
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    expires_at = time.time() + ttl_seconds
    tmp_path = payload_path.with_name(payload_path.name + ".tmp")
    tmp_path.write_bytes(data)
    tmp_path.replace(payload_path)
    expires_path.write_text(str(expires_at))


# Default TTLs
TTL_VCEK_SECONDS = 30 * 86400  # 30 days — VCEK is stable per (chip, TCB) tuple
TTL_CHAIN_SECONDS = 30 * 86400  # 30 days — AMD CA chain very rarely rotates
TTL_CRL_SECONDS = 7 * 86400     # 7 days — matches AMD's typical nextUpdate window
