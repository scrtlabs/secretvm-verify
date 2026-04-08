"""
Attestation verification library for Intel TDX, AMD SEV-SNP, and NVIDIA GPU.

Public API:
    check_secret_vm(url: str, product: str = "") -> AttestationResult
    check_cpu_attestation(data: str, product: str = "") -> AttestationResult
    check_tdx_cpu_attestation(data: str) -> AttestationResult
    check_sev_cpu_attestation(data: str, product: str = "") -> AttestationResult
    check_nvidia_gpu_attestation(data: str) -> AttestationResult

Each function accepts the raw text content of the attestation quote file
(hex-encoded for TDX, base64-encoded for AMD, JSON for NVIDIA) and returns
an AttestationResult with verification status, individual checks, parsed
report fields, and any errors.
"""

# Third-party imports needed at package level for test mocking compatibility
import requests  # noqa: F401

# Types
from .types import AttestationResult, WorkloadResult, AgentMetadata, AgentService

# TDX
from .tdx import check_tdx_cpu_attestation

# AMD SEV-SNP
from .amd import check_sev_cpu_attestation

# CPU auto-detect
from .cpu import check_cpu_attestation

# NVIDIA GPU
from .nvidia import check_nvidia_gpu_attestation

# Secret VM
# Public API
from .vm import check_secret_vm
# Internal imports needed for test mocking via _get_pkg() pattern in vm.py
from .vm import _get_tls_cert_fingerprint, _extract_docker_compose  # noqa: F401

# Workload verification
from .workload import (
    resolve_secretvm_version,
    verify_tdx_workload,
    verify_sev_workload,
    verify_workload,
    format_workload_result,
)

# ERC-8004 Agent verification
from .agent import (
    resolve_agent,
    verify_agent,
    check_agent,
    get_chain_config,
    get_rpc_url,
    list_chains,
)

__all__ = [
    # Types
    "AttestationResult",
    "WorkloadResult",
    "AgentMetadata",
    "AgentService",
    # TDX
    "check_tdx_cpu_attestation",
    # AMD
    "check_sev_cpu_attestation",
    # CPU
    "check_cpu_attestation",
    # NVIDIA
    "check_nvidia_gpu_attestation",
    # VM
    "check_secret_vm",
    # Workload
    "resolve_secretvm_version",
    "verify_tdx_workload",
    "verify_sev_workload",
    "verify_workload",
    "format_workload_result",
    # Agent
    "resolve_agent",
    "verify_agent",
    "check_agent",
    "get_chain_config",
    "get_rpc_url",
    "list_chains",
]
