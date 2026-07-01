"""ERC-8004 agent verification."""

import asyncio
import base64
import json
from typing import Optional

import requests

from .types import AttestationResult, AgentService, AgentMetadata, order_checks
from .cpu import check_cpu_attestation
from .nvidia import check_nvidia_gpu_attestation
from .workload import verify_workload
from .vm import _get_tls_cert_fingerprint, _parse_service_base_url, _parse_tls_endpoint

_DEFAULT_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
_SEPOLIA_REGISTRY = "0x8004A818BFB912233c491871b3d84c89A494BD9e"

_CHAINS: dict[str, dict] = {
    "ethereum":  {"chain_id": 1,        "name": "Ethereum",        "registry": _DEFAULT_REGISTRY},
    "base":      {"chain_id": 8453,     "name": "Base",            "registry": _DEFAULT_REGISTRY},
    "arbitrum":  {"chain_id": 42161,    "name": "Arbitrum",        "registry": _DEFAULT_REGISTRY},
    "sepolia":   {"chain_id": 11155111, "name": "Sepolia",         "registry": _SEPOLIA_REGISTRY},
    "polygon":   {"chain_id": 137,      "name": "Polygon",         "registry": _DEFAULT_REGISTRY},
    "bnb":       {"chain_id": 56,       "name": "BNB Smart Chain", "registry": _DEFAULT_REGISTRY},
    "gnosis":    {"chain_id": 100,      "name": "Gnosis",          "registry": _DEFAULT_REGISTRY},
    "linea":     {"chain_id": 59144,    "name": "Linea",           "registry": _DEFAULT_REGISTRY},
    "taiko":     {"chain_id": 167000,   "name": "Taiko",           "registry": _DEFAULT_REGISTRY},
    "celo":      {"chain_id": 42220,    "name": "Celo",            "registry": _DEFAULT_REGISTRY},
    "avalanche": {"chain_id": 43114,    "name": "Avalanche",       "registry": _DEFAULT_REGISTRY},
    "optimism":  {"chain_id": 10,       "name": "Optimism",        "registry": _DEFAULT_REGISTRY},
    "abstract":  {"chain_id": 2741,     "name": "Abstract",        "registry": _DEFAULT_REGISTRY},
    "megaeth":   {"chain_id": 1000001,  "name": "MegaETH",         "registry": _DEFAULT_REGISTRY},
    "mantle":    {"chain_id": 5000,     "name": "Mantle",          "registry": _DEFAULT_REGISTRY},
    "soneium":   {"chain_id": 1946,     "name": "Soneium",         "registry": _DEFAULT_REGISTRY},
    "xlayer":    {"chain_id": 196,      "name": "X Layer",         "registry": _DEFAULT_REGISTRY},
    "metis":     {"chain_id": 1088,     "name": "Metis",           "registry": _DEFAULT_REGISTRY},
}

_REGISTRY_ABI = [
    {
        "inputs": [{"name": "tokenId", "type": "uint256"}],
        "name": "tokenURI",
        "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "agentId", "type": "uint256"}],
        "name": "agentURI",
        "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def get_chain_config(chain: str) -> dict:
    """Get chain configuration by name."""
    config = _CHAINS.get(chain.lower())
    if not config:
        valid = ", ".join(_CHAINS.keys())
        raise ValueError(f'Unknown chain "{chain}". Supported: {valid}')
    return config


def get_rpc_url(chain: str) -> str:
    """Resolve the RPC URL for a chain.

    Priority:
        1. SECRETVM_RPC_<CHAIN> env var (e.g. SECRETVM_RPC_BASE)
        2. SECRETVM_RPC_URL env var (generic fallback)

    Raises:
        RuntimeError: If no RPC URL is configured for the chain.
    """
    import os
    env_key = f"SECRETVM_RPC_{chain.upper()}"
    if os.environ.get(env_key):
        return os.environ[env_key]
    if os.environ.get("SECRETVM_RPC_URL"):
        return os.environ["SECRETVM_RPC_URL"]
    raise RuntimeError(
        f"No RPC URL configured for {chain}. "
        f"Set the {env_key} or SECRETVM_RPC_URL environment variable."
    )


def list_chains() -> list[str]:
    """Return list of supported chain names."""
    return list(_CHAINS.keys())


def _normalize_agent_services(raw) -> list[AgentService]:
    if not isinstance(raw, list):
        return []
    result = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "") or f"service-{i + 1}"
        endpoint = entry.get("endpoint", "")
        description = entry.get("description", "")
        result.append(AgentService(name=str(name), endpoint=str(endpoint), description=str(description)))
    return result


def _find_required_unique_service(services: list[AgentService], service_name: str) -> tuple[Optional[str], Optional[str]]:
    matches = [
        s.endpoint.strip()
        for s in services
        if s.name.lower() == service_name and s.endpoint.strip()
    ]
    if not matches:
        return None, f"No {service_name} service endpoint found in agent metadata"
    if len(matches) > 1:
        return None, f"Multiple {service_name} service endpoints found in agent metadata"
    return matches[0], None


def _find_optional_unique_service(services: list[AgentService], service_name: str) -> tuple[Optional[str], Optional[str]]:
    matches = [
        s.endpoint.strip()
        for s in services
        if s.name.lower() == service_name and s.endpoint.strip()
    ]
    if len(matches) > 1:
        return None, f"Multiple {service_name} service endpoints found in agent metadata"
    return (matches[0] if matches else None), None


def resolve_agent(agent_id: int, chain: str) -> AgentMetadata:
    """Resolve an ERC-8004 agent's metadata from the on-chain registry.

    Queries the registry contract for the agent's tokenURI, fetches the
    metadata JSON, and returns a normalized AgentMetadata object.

    Args:
        agent_id: The agent's on-chain token ID.
        chain: Chain name (e.g. "base", "ethereum", "arbitrum").

    Returns:
        AgentMetadata with name, services, and supported_trust.
    """
    from web3 import Web3

    chain_config = get_chain_config(chain)
    rpc_url = get_rpc_url(chain)
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(chain_config["registry"]),
        abi=_REGISTRY_ABI,
    )

    token_uri = None
    try:
        token_uri = contract.functions.tokenURI(agent_id).call()
    except Exception:
        try:
            token_uri = contract.functions.agentURI(agent_id).call()
        except Exception:
            raise RuntimeError(
                f"Could not find tokenURI or agentURI for agent {agent_id} on {chain_config['name']}"
            )

    if not token_uri or not token_uri.strip():
        raise RuntimeError(f"Registry returned empty tokenURI for agent {agent_id}")

    fetch_url = token_uri
    if fetch_url.startswith("data:"):
        # Handle data URIs (e.g. data:application/json;base64,...)
        _, encoded = fetch_url.split(",", 1)
        manifest = json.loads(base64.b64decode(encoded))
    else:
        if fetch_url.startswith("ipfs://"):
            fetch_url = fetch_url.replace("ipfs://", "https://ipfs.io/ipfs/")
        resp = requests.get(fetch_url, timeout=15)
        resp.raise_for_status()
        manifest = resp.json()

    trust = manifest.get("supportedTrust") or manifest.get("supported_trust") or []
    services_raw = manifest.get("services") or manifest.get("endpoints") or []

    name = manifest.get("name", "")
    if not isinstance(name, str) or not name.strip():
        name = f"Agent {agent_id}"

    description = manifest.get("description", "")
    if not isinstance(description, str):
        description = ""

    return AgentMetadata(
        name=name,
        description=description,
        supported_trust=trust if isinstance(trust, list) else [],
        services=_normalize_agent_services(services_raw),
        image=str(manifest.get("image", "")),
        type=str(manifest.get("type", "")),
        active=bool(manifest.get("active", True)),
        x402_support=bool(manifest.get("x402Support", False)),
        attributes=manifest.get("attributes", {}),
        raw=manifest,
    )


def verify_agent(
    metadata: AgentMetadata,
    reload_amd_kds: bool = False,
    check_proof_of_cloud: bool = False,
    strict: bool = False,
) -> AttestationResult:
    """Verify an ERC-8004 agent given its metadata.

    Discovers teequote and workload endpoints from the metadata, then runs
    the full verification flow: TLS cert, CPU quote, TLS binding, GPU quote,
    GPU binding, and workload verification.

    Args:
        metadata: AgentMetadata with name, services, and supported_trust.
        reload_amd_kds: If True, bypass the local AMD KDS cache and re-fetch
            VCEK / cert chain / CRL. No effect on TDX agents.

    Returns:
        AttestationResult with attestation_type="ERC-8004".
    """
    errors = []
    checks = {}
    report = {}

    report["agent_name"] = metadata.name

    # 1. Validate metadata
    has_tee = "tee-attestation" in [t.lower() for t in metadata.supported_trust]
    if not has_tee:
        errors.append("Agent does not support tee-attestation")
        checks["metadata_valid"] = False
        return AttestationResult(
            valid=False, attestation_type="ERC-8004",
            checks=order_checks(checks), report=report, errors=errors,
        )

    teequote_endpoint, service_error = _find_required_unique_service(metadata.services, "teequote")
    if service_error or not teequote_endpoint:
        errors.append(service_error or "No teequote service endpoint found in agent metadata")
        checks["metadata_valid"] = False
        return AttestationResult(
            valid=False, attestation_type="ERC-8004",
            checks=order_checks(checks), report=report, errors=errors,
        )

    inference_endpoint, service_error = _find_required_unique_service(metadata.services, "inference")
    if service_error or not inference_endpoint:
        errors.append(service_error or "No inference service endpoint found in agent metadata")
        checks["metadata_valid"] = False
        return AttestationResult(
            valid=False, attestation_type="ERC-8004",
            checks=order_checks(checks), report=report, errors=errors,
        )

    workload_service, service_error = _find_optional_unique_service(metadata.services, "workload")
    if service_error:
        errors.append(service_error)
        checks["metadata_valid"] = False
        return AttestationResult(
            valid=False, attestation_type="ERC-8004",
            checks=order_checks(checks), report=report, errors=errors,
        )
    workload_base_url = None
    if workload_service:
        try:
            workload_base_url = _parse_service_base_url(
                workload_service,
                label="workload service endpoint",
            ).base_url
        except Exception as e:
            errors.append(str(e))
            checks["metadata_valid"] = False
            return AttestationResult(
                valid=False, attestation_type="ERC-8004",
                checks=order_checks(checks), report=report, errors=errors,
            )
    checks["metadata_valid"] = True

    # 2. Derive URLs
    try:
        attestation_endpoint = _parse_service_base_url(teequote_endpoint, label="teequote service endpoint")
        tls_endpoint = _parse_tls_endpoint(inference_endpoint, label="inference service endpoint")
    except Exception as e:
        errors.append(str(e))
        checks["metadata_valid"] = False
        return AttestationResult(
            valid=False, attestation_type="ERC-8004",
            checks=order_checks(checks), report=report, errors=errors,
        )

    base_url = attestation_endpoint.base_url
    cpu_url = f"{base_url}/cpu"
    gpu_url = f"{base_url}/gpu"
    workload_url = f"{workload_base_url or base_url}/docker-compose"

    report["attestation_url"] = attestation_endpoint.base_url
    report["tls_binding_url"] = tls_endpoint.base_url
    report["tls_binding_service"] = "inference"

    # 3. TLS certificate SPKI fingerprint
    try:
        tls_spki_fingerprint = _get_tls_cert_fingerprint(tls_endpoint.host, tls_endpoint.port)
        checks["tls_cert_fetched"] = True
        report["tls_spki_fingerprint"] = tls_spki_fingerprint.hex()
    except Exception as e:
        errors.append(f"Failed to get TLS certificate: {e}")
        checks["tls_cert_fetched"] = False
        return AttestationResult(
            valid=False, attestation_type="ERC-8004",
            checks=order_checks(checks), report=report, errors=errors,
        )

    # 4. Fetch and verify CPU quote
    try:
        resp = requests.get(cpu_url, timeout=15, verify=True)
        resp.raise_for_status()
        cpu_data = resp.text
        checks["cpu_quote_fetched"] = True
    except Exception as e:
        errors.append(f"Failed to fetch CPU quote: {e}")
        checks["cpu_quote_fetched"] = False
        return AttestationResult(
            valid=False, attestation_type="ERC-8004",
            checks=order_checks(checks), report=report, errors=errors,
        )

    cpu_result = check_cpu_attestation(cpu_data, reload_amd_kds=reload_amd_kds, strict=strict)
    checks["cpu_quote_verified"] = cpu_result.valid
    report["cpu"] = cpu_result.report
    report["cpu_type"] = cpu_result.attestation_type
    if not cpu_result.valid:
        errors.extend(cpu_result.errors)

    # 5. TLS binding
    report_data_hex = cpu_result.report.get("report_data", "")
    if len(report_data_hex) >= 64:
        first_half = report_data_hex[:64]
        checks["tls_binding_verified"] = first_half == tls_spki_fingerprint.hex()
        if not checks["tls_binding_verified"]:
            errors.append(
                f"TLS binding failed: report_data first half ({first_half[:16]}...) "
                f"!= TLS SPKI fingerprint ({tls_spki_fingerprint.hex()[:16]}...)"
            )
    else:
        checks["tls_binding_verified"] = False
        errors.append("report_data too short for TLS binding check")

    gpu_data = ""
    gpu_json = None
    try:
        resp = requests.get(gpu_url, timeout=15, verify=True)
        resp.raise_for_status()
        gpu_json = json.loads(resp.text)
        if "error" in gpu_json:
            raise ValueError(str(gpu_json["error"]))
        if not isinstance(gpu_json.get("nonce"), str) or not gpu_json["nonce"]:
            raise ValueError("GPU attestation missing nonce")
        checks["gpu_quote_fetched"] = True
        gpu_data = resp.text
    except Exception as e:
        errors.append(f"Failed to fetch GPU attestation: {e}")
        checks["gpu_quote_fetched"] = False
        checks["gpu_quote_verified"] = False
        checks["gpu_binding_verified"] = False

    if checks.get("gpu_quote_fetched"):
        try:
            gpu_result = check_nvidia_gpu_attestation(gpu_data)
        except Exception as e:
            gpu_result = AttestationResult(
                valid=False, attestation_type="NVIDIA-GPU",
                checks={}, report={}, errors=[f"GPU attestation verification failed: {e}"],
            )
        checks["gpu_quote_verified"] = gpu_result.valid
        report["gpu"] = gpu_result.report
        if not gpu_result.valid:
            errors.extend(gpu_result.errors)

        gpu_nonce = gpu_json.get("nonce", "")
        if len(report_data_hex) >= 128:
            second_half = report_data_hex[64:128]
            checks["gpu_binding_verified"] = second_half == gpu_nonce
            if not checks["gpu_binding_verified"]:
                errors.append(
                    f"GPU binding failed: report_data second half ({second_half[:16]}...) "
                    f"!= GPU nonce ({gpu_nonce[:16]}...)"
                )
        else:
            checks["gpu_binding_verified"] = False
            errors.append("report_data too short for GPU binding check")

    # 7. Workload verification
    try:
        resp = requests.get(workload_url, timeout=15, verify=True)
        resp.raise_for_status()
        docker_compose = resp.text
        checks["workload_fetched"] = True

        workload_result = verify_workload(cpu_data, docker_compose)
        checks["workload_binding_verified"] = workload_result.status == "authentic_match"
        report["workload"] = {
            "status": workload_result.status,
            "template_name": workload_result.template_name,
            "artifacts_ver": workload_result.artifacts_ver,
            "env": workload_result.env,
        }
        report["docker_compose"] = docker_compose
        if workload_result.status == "authentic_mismatch":
            errors.append("Workload mismatch: VM is authentic but docker-compose does not match")
        elif workload_result.status == "not_authentic":
            errors.append("Workload verification failed: not an authentic SecretVM")
    except Exception as e:
        errors.append(f"Failed to fetch workload: {e}")
        checks["workload_fetched"] = False

    # 8. Proof of cloud (opt-in): confirm the quote was produced on a Secret VM.
    # Resolve via sys.modules so tests can patch `secretvm.verify.check_proof_of_cloud`
    # (same pattern as vm.py).
    if check_proof_of_cloud:
        import sys as _sys
        poc_result = _sys.modules["secretvm.verify"].check_proof_of_cloud(cpu_data)
        checks["proof_of_cloud_verified"] = poc_result.valid
        if poc_result.report.get("proof_of_cloud") is not None:
            report["proof_of_cloud"] = poc_result.report["proof_of_cloud"]
        if not poc_result.valid:
            errors.extend(poc_result.errors)

    # Overall validity
    required_checks = [
        checks.get("metadata_valid"),
        checks.get("tls_cert_fetched"),
        checks.get("cpu_quote_fetched"),
        checks.get("cpu_quote_verified"),
        checks.get("tls_binding_verified"),
        checks.get("gpu_quote_fetched"),
        checks.get("gpu_quote_verified"),
        checks.get("gpu_binding_verified"),
        checks.get("workload_binding_verified", False),
    ]
    if check_proof_of_cloud:
        required_checks.append(checks.get("proof_of_cloud_verified", False))

    valid = all(required_checks)

    return AttestationResult(
        valid=valid, attestation_type="ERC-8004",
        checks=order_checks(checks), report=report, errors=errors,
    )


def check_agent(
    agent_id: int,
    chain: str,
    reload_amd_kds: bool = False,
    check_proof_of_cloud: bool = False,
    strict: bool = False,
) -> AttestationResult:
    """End-to-end ERC-8004 agent verification.

    Resolves the agent's metadata from the on-chain registry, then runs
    the full verification flow via verify_agent.

    Args:
        agent_id: The agent's on-chain token ID.
        chain: Chain name (e.g. "base", "ethereum", "arbitrum").
        reload_amd_kds: If True, bypass the local AMD KDS cache and re-fetch
            VCEK / cert chain / CRL. No effect on TDX agents.
        strict: If True, fail closed when AMD KDS is unreachable rather
            than falling back to a stale cached entry. No effect on TDX.

    Returns:
        AttestationResult with attestation_type="ERC-8004".
    """
    try:
        metadata = resolve_agent(agent_id, chain)
    except Exception as e:
        return AttestationResult(
            valid=False, attestation_type="ERC-8004",
            checks={"agent_resolved": False},
            errors=[f"Failed to resolve agent: {e}"],
        )

    result = verify_agent(
        metadata,
        reload_amd_kds=reload_amd_kds,
        check_proof_of_cloud=check_proof_of_cloud,
        strict=strict,
    )
    result.checks = {"agent_resolved": True, **result.checks}
    return result


async def verify_agent_async(
    metadata: AgentMetadata,
    reload_amd_kds: bool = False,
    check_proof_of_cloud: bool = False,
    strict: bool = False,
) -> AttestationResult:
    """Async variant of :func:`verify_agent`.

    Use this from inside an event loop. The current implementation offloads
    the synchronous wrapper to a thread pool via :func:`asyncio.to_thread`.
    """
    return await asyncio.to_thread(
        verify_agent, metadata, reload_amd_kds, check_proof_of_cloud, strict,
    )


async def check_agent_async(
    agent_id: int,
    chain: str,
    reload_amd_kds: bool = False,
    check_proof_of_cloud: bool = False,
    strict: bool = False,
) -> AttestationResult:
    """Async variant of :func:`check_agent`.

    Use this from inside an event loop. The current implementation offloads
    the synchronous wrapper (on-chain resolution + TEE verification) to a
    thread pool via :func:`asyncio.to_thread`.
    """
    return await asyncio.to_thread(
        check_agent, agent_id, chain, reload_amd_kds, check_proof_of_cloud, strict,
    )
