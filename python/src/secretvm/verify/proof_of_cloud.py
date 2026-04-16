"""Proof-of-Cloud verification against the SCRT Labs quote-parse endpoint."""

import asyncio

import requests

from .types import AttestationResult, order_checks

_POC_URL = "https://secretai.scrtlabs.com/api/quote-parse"


def _curate_response(body: dict) -> dict:
    """Return a display-friendly subset of the quote-parse response.

    The full response contains ~35KB of `collateral` hex and a redundant
    `quote` dump that overlaps with our own QVL parse. We keep only the
    fields that distinguish proof-of-cloud from a plain DCAP verification.
    """
    quote = body.get("quote") or {}
    return {
        "origin": body.get("origin"),
        "proof_of_cloud": body.get("proof_of_cloud"),
        "status": body.get("status"),
        "machine_id": quote.get("machine_id") if isinstance(quote, dict) else None,
    }


def check_proof_of_cloud(quote: str) -> AttestationResult:
    """Verify a CPU quote against SCRT Labs' proof-of-cloud endpoint.

    Args:
        quote: Raw CPU quote text as served by the VM's /cpu endpoint.

    Returns:
        AttestationResult with attestation_type="PROOF-OF-CLOUD". The single
        check `proof_of_cloud_verified` is True iff the endpoint returned
        HTTP 200 and `proof_of_cloud: true`.
    """
    checks: dict = {}
    report: dict = {}
    errors: list = []

    try:
        resp = requests.post(
            _POC_URL,
            json={"quote": quote.strip()},
            timeout=30,
        )
    except Exception as e:
        errors.append(f"Failed to reach proof-of-cloud endpoint: {e}")
        checks["proof_of_cloud_verified"] = False
        return AttestationResult(
            valid=False, attestation_type="PROOF-OF-CLOUD",
            checks=order_checks(checks), report=report, errors=errors,
        )

    if resp.status_code != 200:
        errors.append(
            f"Proof-of-cloud endpoint returned HTTP {resp.status_code}"
        )
        checks["proof_of_cloud_verified"] = False
        return AttestationResult(
            valid=False, attestation_type="PROOF-OF-CLOUD",
            checks=order_checks(checks), report=report, errors=errors,
        )

    try:
        body = resp.json()
    except Exception as e:
        errors.append(f"Proof-of-cloud response was not valid JSON: {e}")
        checks["proof_of_cloud_verified"] = False
        return AttestationResult(
            valid=False, attestation_type="PROOF-OF-CLOUD",
            checks=order_checks(checks), report=report, errors=errors,
        )

    report["proof_of_cloud"] = _curate_response(body)
    passed = bool(body.get("proof_of_cloud"))
    checks["proof_of_cloud_verified"] = passed
    if not passed:
        errors.append("Proof-of-cloud endpoint reported proof_of_cloud=false")

    return AttestationResult(
        valid=passed, attestation_type="PROOF-OF-CLOUD",
        checks=order_checks(checks), report=report, errors=errors,
    )


async def check_proof_of_cloud_async(quote: str) -> AttestationResult:
    """Async variant of check_proof_of_cloud (offloads the sync POST)."""
    return await asyncio.to_thread(check_proof_of_cloud, quote)
