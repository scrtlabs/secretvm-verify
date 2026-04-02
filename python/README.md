# secretvm-verify

Attestation verification SDK for confidential computing environments. Verifies Intel TDX, AMD SEV-SNP, and NVIDIA GPU attestation quotes, with end-to-end Secret VM verification that validates CPU attestation, GPU attestation, and the cryptographic bindings between them.

## What it verifies

- **Intel TDX** — Parses a TDX Quote v4, verifies the ECDSA-P256 signature chain (PCK -> Intermediate -> Root), validates QE report binding, and checks TCB status against Intel's Provisioning Certification Service.
- **AMD SEV-SNP** — Parses a SEV-SNP attestation report, fetches the VCEK certificate from AMD's Key Distribution Service, verifies the ECDSA-P384 report signature, and validates the certificate chain (VCEK -> ASK -> ARK).
- **NVIDIA GPU** — Submits GPU attestation evidence to NVIDIA's Remote Attestation Service (NRAS), verifies the returned JWT signatures against NVIDIA's published JWKS keys, and extracts per-GPU attestation claims.
- **SecretVM workload** — Given a TDX or SEV-SNP quote and a `docker-compose.yaml`, determines whether the quote was produced by a known SecretVM image and verifies the exact compose file that was booted.
- **Secret VM** — End-to-end verification that connects to a VM's attestation endpoints, verifies CPU and GPU attestation, and validates TLS and GPU cryptographic bindings.
- **ERC-8004 Agent verification** — End-to-end verification of on-chain AI agents registered under the [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) standard. Resolves agent metadata from any supported blockchain (Ethereum, Base, Arbitrum, Polygon, and 14 more), discovers the agent's TEE attestation endpoints, and runs the full verification flow. Three composable functions:
  - **`resolve_agent`** — Queries the on-chain registry contract for the agent's metadata.
  - **`verify_agent`** — Takes agent metadata and runs full TEE verification against the agent's declared endpoints.
  - **`check_agent`** — End-to-end: resolves the agent on-chain, then verifies it.

## Installation

```bash
pip install secretvm-verify
```

## Quick start

### Verify a Secret VM (recommended)

The simplest way to verify a VM — handles CPU detection, GPU detection, and all binding checks automatically.

```python
from secretvm.verify import check_secret_vm

result = check_secret_vm("my-vm.example.com")

print(result.valid)           # True if all checks pass
print(result.attestation_type) # "SECRET-VM"
print(result.checks)          # {"tls_cert_obtained": True, "cpu_attestation_valid": True, ...}
print(result.report)          # {"tls_fingerprint": "...", "cpu": {...}, "cpu_type": "TDX", ...}
print(result.errors)          # [] if no errors
```

### Verify an ERC-8004 agent

Verify an AI agent registered on-chain using the ERC-8004 standard. Supports 18 chains including Ethereum, Base, Arbitrum, and more.

```python
from secretvm.verify import check_agent

# End-to-end: resolve on-chain + verify TEE attestation
result = check_agent(38114, "base")

print(result.valid)            # True if all checks pass
print(result.attestation_type) # "ERC-8004"
print(result.checks)          # {"agent_resolved": True, "metadata_valid": True, ...}
```

You can also work with the individual steps:

```python
from secretvm.verify import resolve_agent, verify_agent

# Step 1: Resolve agent metadata from the blockchain
metadata = resolve_agent(38114, "base")
print(metadata.name)             # Agent name
print(metadata.services)         # [AgentService(name="teequote", endpoint="..."), ...]
print(metadata.supported_trust)  # ["tee-attestation"]

# Step 2: Verify the agent's TEE attestation
result = verify_agent(metadata)
```

**RPC configuration:** Set `SECRETVM_RPC_BASE` (or `SECRETVM_RPC_<CHAIN>`) environment variable to use your own RPC endpoint. Falls back to public RPCs if not set.

### Resolve SecretVM version from a quote

Given a TDX or SEV-SNP quote, determine which official SecretVM template and version produced it:

```python
from secretvm.verify import resolve_secretvm_version

result = resolve_secretvm_version(open("cpu_quote.txt").read())
if result:
    print(result["template_name"])  # e.g. "small"
    print(result["artifacts_ver"])  # e.g. "v0.0.25"
else:
    print("Not a known SecretVM")
```

### Verify a workload (quote + docker-compose)

Verify that a quote was produced by a known SecretVM *and* that it was running a specific `docker-compose.yaml`:

```python
from secretvm.verify import verify_workload, format_workload_result

# Auto-detects TDX vs SEV-SNP:
result = verify_workload(
    open("cpu_quote.txt").read(),
    open("docker-compose.yaml").read(),
)

print(result.status)        # "authentic_match" | "authentic_mismatch" | "not_authentic"
print(result.template_name) # e.g. "small"  (None when not_authentic)
print(result.artifacts_ver) # e.g. "v0.0.25" (None when not_authentic)
print(result.env)           # e.g. "prod"    (None when not_authentic)
print(format_workload_result(result))  # human-readable summary
```

### Verify a CPU quote (auto-detect TDX vs SEV-SNP)

All verification functions accept either raw quote data or a VM URL. When a URL is passed, the quote is automatically fetched from the VM's attestation endpoint.

```python
from secretvm.verify import check_cpu_attestation

# From a file:
result = check_cpu_attestation(open("cpu_quote.txt").read())

# Or directly from a VM URL:
result = check_cpu_attestation("blue-moose.vm.scrtlabs.com")

print(result.attestation_type)  # "TDX" or "SEV-SNP"
print(result.valid)
```

This works with all functions: `check_tdx_cpu_attestation`, `check_sev_cpu_attestation`, `check_nvidia_gpu_attestation`, `verify_workload`, `resolve_secretvm_version`. When a URL is passed to `verify_workload`, both the quote and docker-compose are fetched automatically.

## API reference

### `AttestationResult`

All functions return an `AttestationResult` with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `bool` | Overall pass/fail |
| `attestation_type` | `str` | `"TDX"`, `"SEV-SNP"`, `"NVIDIA-GPU"`, or `"SECRET-VM"` |
| `checks` | `dict` | Individual verification steps |
| `report` | `dict` | Parsed attestation fields |
| `errors` | `list` | Error messages for failed checks |

### Functions

#### `check_secret_vm(url, product="")`

End-to-end Secret VM verification. Connects to `<url>:29343`, fetches CPU and GPU quotes, verifies both, and checks TLS and GPU bindings.

**Parameters:**
- `url` — VM address (e.g., `"my-vm.example.com"`, `"https://my-vm:29343"`)
- `product` — AMD product name (`"Genoa"`, `"Milan"`, `"Turin"`). Only needed for SEV-SNP, auto-detected if omitted.

#### `check_cpu_attestation(data, product="")`

Auto-detects Intel TDX vs AMD SEV-SNP and delegates to the appropriate function.

#### `check_tdx_cpu_attestation(data)`

Verifies an Intel TDX Quote v4.

#### `check_sev_cpu_attestation(data, product="")`

Verifies an AMD SEV-SNP attestation report.

#### `check_nvidia_gpu_attestation(data)`

Verifies NVIDIA GPU attestation via NRAS.

#### `resolve_secretvm_version(data)`

Looks up a quote in the SecretVM artifact registry. Returns the matching template name and version, or `None` if not found.

#### `verify_workload(data, docker_compose_yaml)`

Auto-detects quote type and verifies that it was produced by a known SecretVM running the given docker-compose.

#### `verify_tdx_workload(data, docker_compose_yaml)`

TDX-specific workload verification.

#### `verify_sev_workload(data, docker_compose_yaml)`

SEV-SNP-specific workload verification.

#### `format_workload_result(result)`

Formats a `WorkloadResult` as a human-readable string.

### `WorkloadResult`

| Field | Type | Description |
|-------|------|-------------|
| `status` | `str` | `"authentic_match"`, `"authentic_mismatch"`, or `"not_authentic"` |
| `template_name` | `str \| None` | SecretVM template (e.g. `"small"`) |
| `artifacts_ver` | `str \| None` | Artifacts version (e.g. `"v0.0.25"`) |
| `env` | `str \| None` | Environment (e.g. `"prod"`) |

### ERC-8004 Agent Functions

#### `check_agent(agent_id, chain)`

End-to-end ERC-8004 agent verification. Resolves agent metadata from the on-chain registry, then verifies TEE attestation.

#### `resolve_agent(agent_id, chain)`

Resolves an agent's metadata from the on-chain registry contract. Returns an `AgentMetadata` dataclass.

#### `verify_agent(metadata)`

Verifies an ERC-8004 agent given its metadata. Discovers teequote/workload endpoints and runs the full verification flow.

### `AgentMetadata`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Agent name |
| `description` | `str` | Agent description |
| `supported_trust` | `list[str]` | Trust models (must include `"tee-attestation"`) |
| `services` | `list[AgentService]` | Service endpoints (`name` + `endpoint`) |

### RPC Configuration

An RPC URL **must** be provided via environment variable to use the ERC-8004 agent functions. No default RPCs are shipped with the package.

Set one of:
- `SECRETVM_RPC_<CHAIN>` — chain-specific (e.g. `SECRETVM_RPC_BASE`, `SECRETVM_RPC_ETHEREUM`)
- `SECRETVM_RPC_URL` — generic fallback for all chains

Example:
```bash
export SECRETVM_RPC_BASE="https://base-mainnet.g.alchemy.com/v2/YOUR_KEY"
```

Supported chains: ethereum, base, arbitrum, sepolia, polygon, bnb, gnosis, linea, taiko, celo, avalanche, optimism, abstract, megaeth, mantle, soneium, xlayer, metis.

## CLI usage

```bash
cd python
pip install -e .
python check_vm.py https://my-vm:29343
python check_vm.py https://my-vm:29343 --raw     # JSON output
python check_vm.py https://my-vm:29343 --product Genoa
```

## External services

The library contacts these services during verification:

| Service | Used by | Purpose |
|---------|---------|---------|
| [Intel PCS](https://api.trustedservices.intel.com) | TDX | TCB status lookup |
| [AMD KDS](https://kdsintf.amd.com) | SEV-SNP | VCEK certificate and cert chain |
| [NVIDIA NRAS](https://nras.attestation.nvidia.com) | GPU | GPU attestation verification |

**Note:** AMD KDS has rate limits. If you encounter 429 errors, specify the `product` parameter to reduce the number of requests.

## Requirements

- Python >= 3.10
- `requests`, `cryptography`, `PyYAML`, `web3`
- `openssl` CLI (required for AMD SEV-SNP certificate chain verification)

## License

MIT
