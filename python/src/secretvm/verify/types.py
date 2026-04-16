"""Shared data types for the secretvm.verify package."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AttestationResult:
    valid: bool
    attestation_type: str  # "TDX", "SEV-SNP", "NVIDIA-GPU"
    checks: dict = field(default_factory=dict)
    report: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


# Canonical ordering for the per-check list. Keys are inserted into the final
# `result.checks` dict in this order; any unlisted keys are appended at the end.
_CHECK_ORDER = (
    "metadata_valid",
    "cpu_quote_fetched",
    "tls_cert_fetched",
    # TDX-specific detail keys
    "quote_parsed",
    "quote_verified",
    # SEV-specific detail keys
    "report_parsed",
    "vcek_fetched",
    "cert_chain_valid",
    "crl_check_passed",
    "report_signature_valid",
    # VM-level rollup
    "cpu_quote_verified",
    "tls_binding_verified",
    "gpu_quote_fetched",
    "gpu_quote_verified",
    "gpu_binding_verified",
    "workload_fetched",
    "workload_binding_verified",
    "proof_of_cloud_verified",
)


def order_checks(checks: dict) -> dict:
    out: dict = {}
    for key in _CHECK_ORDER:
        if key in checks:
            out[key] = checks[key]
    for key, value in checks.items():
        if key not in out:
            out[key] = value
    return out


@dataclass
class WorkloadResult:
    """Result of a SecretVM workload verification."""
    status: str  # "authentic_match" | "authentic_mismatch" | "not_authentic"
    template_name: Optional[str] = None
    vm_type: Optional[str] = None
    artifacts_ver: Optional[str] = None
    env: Optional[str] = None


@dataclass
class AgentService:
    name: str
    endpoint: str
    description: str = ""


@dataclass
class AgentMetadata:
    name: str
    supported_trust: list[str]
    services: list[AgentService]
    description: str = ""
    image: str = ""
    type: str = ""
    active: bool = True
    x402_support: bool = False
    attributes: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
