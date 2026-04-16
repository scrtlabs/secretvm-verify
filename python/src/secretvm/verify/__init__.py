"""
Attestation verification library for Intel TDX, AMD SEV-SNP, and NVIDIA GPU.

Public API:
    check_secret_vm(url: str, product: str = "") -> AttestationResult
    check_cpu_attestation(data: str, product: str = "") -> AttestationResult
    check_tdx_cpu_attestation(data: str) -> AttestationResult
    check_sev_cpu_attestation(data: str, product: str = "") -> AttestationResult
    check_nvidia_gpu_attestation(data: str) -> AttestationResult

Async variants (await from inside an event loop — FastAPI, Jupyter, etc.):
    check_secret_vm_async(url, product="")
    check_cpu_attestation_async(data, product="")
    check_tdx_cpu_attestation_async(data)
    check_sev_cpu_attestation_async(data, product="")
    check_nvidia_gpu_attestation_async(data)
    verify_agent_async(metadata)
    check_agent_async(agent_id, chain)

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
from .tdx import check_tdx_cpu_attestation, check_tdx_cpu_attestation_async

# AMD SEV-SNP
from .amd import check_sev_cpu_attestation, check_sev_cpu_attestation_async

# CPU auto-detect
from .cpu import check_cpu_attestation, check_cpu_attestation_async

# NVIDIA GPU
from .nvidia import check_nvidia_gpu_attestation, check_nvidia_gpu_attestation_async

# Proof of cloud (SCRT Labs quote-parse)
from .proof_of_cloud import check_proof_of_cloud, check_proof_of_cloud_async

# Secret VM
# Public API
from .vm import check_secret_vm, check_secret_vm_async
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
    verify_agent_async,
    check_agent,
    check_agent_async,
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
    "check_tdx_cpu_attestation_async",
    # AMD
    "check_sev_cpu_attestation",
    "check_sev_cpu_attestation_async",
    # CPU
    "check_cpu_attestation",
    "check_cpu_attestation_async",
    # NVIDIA
    "check_nvidia_gpu_attestation",
    "check_nvidia_gpu_attestation_async",
    # VM
    "check_secret_vm",
    "check_secret_vm_async",
    # Proof of cloud
    "check_proof_of_cloud",
    "check_proof_of_cloud_async",
    # Workload
    "resolve_secretvm_version",
    "verify_tdx_workload",
    "verify_sev_workload",
    "verify_workload",
    "format_workload_result",
    # Agent
    "resolve_agent",
    "verify_agent",
    "verify_agent_async",
    "check_agent",
    "check_agent_async",
    "get_chain_config",
    "get_rpc_url",
    "list_chains",
]
