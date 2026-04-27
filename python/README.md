# secretvm-verify

Attestation verification SDK for confidential computing environments. Verifies Intel TDX, AMD SEV-SNP, and NVIDIA GPU attestation quotes, with end-to-end Secret VM verification that validates CPU attestation, GPU attestation, and the cryptographic bindings between them.

## What it verifies

- **Intel TDX** — Performs full Intel DCAP quote verification, delegating the cryptographic checks to the upstream [`dcap-qvl`](https://pypi.org/project/dcap-qvl/) library. Verifies the PCK certificate chain against a pinned Intel SGX Root CA, the QE Identity, PCK CRL and Root CA CRL revocation, the TCB Info signature, the TCB status, the quote signature, and the QE report binding. Collateral (TCB Info, QE Identity, CRLs, issuer chains) is fetched from a Provisioning Certificate Caching Service (PCCS) — defaults to SCRT Labs' deployment. A sync entry point (`check_tdx_cpu_attestation`) and an async entry point (`check_tdx_cpu_attestation_async`) are both exposed; use the async variant from inside an event loop.
- **AMD SEV-SNP** — Parses a SEV-SNP attestation report, fetches the VCEK certificate from AMD's Key Distribution Service, verifies the ECDSA-P384 report signature, and validates the certificate chain (VCEK -> ASK -> ARK).
- **NVIDIA GPU** — Submits GPU attestation evidence to NVIDIA's Remote Attestation Service (NRAS), verifies the returned JWT signatures against NVIDIA's published JWKS keys, and extracts per-GPU attestation claims.
- **SecretVM workload** — Given a TDX or SEV-SNP quote and a `docker-compose.yaml`, determines whether the quote was produced by a known SecretVM image and verifies the exact compose file that was booted.
- **Secret VM** — End-to-end verification that connects to a VM's attestation endpoints, verifies CPU and GPU attestation, and validates TLS and GPU cryptographic bindings.
- **Proof of cloud** — POSTs a CPU quote to SCRT Labs' [`/api/quote-parse`](https://secretai.scrtlabs.com/api/quote-parse) endpoint, which confirms the quote originated on a Secret VM and returns its `origin` and `machine_id`. Opt-in: pass `check_proof_of_cloud=True` to `check_secret_vm` / `check_agent` / `verify_agent`, or use `--proof-of-cloud` on the CLI. A standalone `check_proof_of_cloud` / `check_proof_of_cloud_async` function is also exposed.
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
print(result.checks)          # {"cpu_quote_fetched": True, "tls_cert_fetched": True, ...}
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

#### `check_secret_vm(url, product="", reload_amd_kds=False, check_proof_of_cloud=False)`

End-to-end Secret VM verification. Connects to `<url>:29343`, fetches CPU and GPU quotes, verifies both, and checks TLS and GPU bindings.

**Parameters:**
- `url` — VM address (e.g., `"my-vm.example.com"`, `"https://my-vm:29343"`)
- `product` — AMD product name (`"Genoa"`, `"Milan"`, `"Turin"`). Only needed for SEV-SNP, auto-detected if omitted.
- `reload_amd_kds` — If `True`, bypass the AMD KDS cache (no effect on TDX).
- `check_proof_of_cloud` — If `True`, also POST the quote to SCRT Labs' `/api/quote-parse` endpoint. Opt-in; off by default.

The returned `result.report["docker_compose"]` contains the raw docker-compose the VM served.

#### `check_cpu_attestation(data, product="")`

Auto-detects Intel TDX vs AMD SEV-SNP and delegates to the appropriate function.

#### `check_tdx_cpu_attestation(data)`

Verifies an Intel TDX Quote v4.

#### `check_sev_cpu_attestation(data, product="")`

Verifies an AMD SEV-SNP attestation report.

#### `check_nvidia_gpu_attestation(data)`

Verifies NVIDIA GPU attestation via NRAS.

#### `check_proof_of_cloud(quote)` / `check_proof_of_cloud_async(quote)`

POSTs a raw CPU quote to SCRT Labs' [`/api/quote-parse`](https://secretai.scrtlabs.com/api/quote-parse) endpoint. Returns an `AttestationResult` with `attestation_type="PROOF-OF-CLOUD"` and a single check `proof_of_cloud_verified`. The report exposes `origin`, `proof_of_cloud`, `status`, and `machine_id`. Also runs automatically inside `check_secret_vm`.

The Node CLI also splices this verdict into the output of `--cpu`, `--tdx`, and `--sev` as the `proof_of_cloud_verified` check row.

#### `resolve_secretvm_version(data)`

Looks up a quote in the SecretVM artifact registry. Returns the matching template name and version, or `None` if not found.

#### `verify_workload(data, docker_compose_yaml, docker_files=None, docker_files_sha256=None)`

Auto-detects quote type and verifies that it was produced by a known SecretVM running the given docker-compose. The optional `docker_files` (raw bytes of the archive) or `docker_files_sha256` (hex digest) supports TDX VMs that bake a Dockerfiles archive into the image. SEV-SNP ignores these.

#### `verify_tdx_workload(data, docker_compose_yaml, docker_files=None, docker_files_sha256=None)`

TDX-specific workload verification. When `docker_files` or `docker_files_sha256` is provided, the SHA-256 of the archive is appended to the RTMR3 replay as `log[2]`.

#### `verify_sev_workload(data, docker_compose_yaml, docker_files=None, docker_files_sha256=None)`

SEV-SNP-specific workload verification. When `docker_files` or `docker_files_sha256` is provided, the digest is appended to the kernel cmdline as `docker_additional_files_hash=<hex>` before the SEV-SNP GCTX launch measurement is recomputed.

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
python check_vm.py https://my-vm:29343 --json    # minimal JSON
python check_vm.py https://my-vm:29343 --raw     # full JSON with parsed report
python check_vm.py https://my-vm:29343 --product Genoa
```

## External services

The library contacts these services during verification:

| Service | Used by | Purpose |
|---------|---------|---------|
| [SCRT PCCS](https://pccs.scrtlabs.com) | TDX | DCAP collateral (TCB Info, QE Identity, PCK CRL, Root CA CRL, issuer chains). Override with `SECRETVM_PCCS_URL` (e.g. `https://api.trustedservices.intel.com` for Intel's PCS, or your own deployment). |
| [AMD KDS](https://kdsintf.amd.com) | SEV-SNP | VCEK certificate, AMD CA cert chain (ASK + ARK), CRL |
| [NVIDIA NRAS](https://nras.attestation.nvidia.com) | GPU | GPU attestation verification |

## AMD KDS caching

To minimize calls to `kdsintf.amd.com` (which is rate-limited and returns HTTP 429 under load) the AMD SEV-SNP verifier caches all three KDS responses to disk. The cache is on by default; nothing to enable.

| Item | TTL | Cache key |
|---|---|---|
| VCEK certificate | 30 days | `(product, chip_id, ucode_SPL, snp_SPL, tee_SPL, bl_SPL)` — full TCB tuple |
| AMD CA cert chain (ASK + ARK) | 30 days | `product` |
| CRL | from the CRL's own X.509 `nextUpdate` field (typically ~7 months for AMD); falls back to 7 days if `nextUpdate` is missing or unparseable | `product` |

The VCEK cache key includes the full TCB tuple because AMD issues a distinct VCEK per `(chip, TCB version)`. A microcode update on the same chip becomes a cache miss with the new key, fetching the updated VCEK as expected.

**Cache location.** Default `~/.cache/secretvm-verify/amd/`. Override with the `SECRETVM_VERIFY_CACHE_DIR` environment variable; the library appends `/amd` to whatever you set:

```sh
export SECRETVM_VERIFY_CACHE_DIR=/var/cache/myapp
# → entries land in /var/cache/myapp/amd/{vcek,cert_chain,crl}/
```

Each cached entry is two files: the payload (DER bytes for VCEK and CRL, PEM text for the cert chain) and a sidecar `<name>.expires` containing the Unix-epoch expiration time.

**Inspect cached entries:**

```sh
ls -lR ~/.cache/secretvm-verify/amd/

# Decode a specific VCEK
openssl x509 -in ~/.cache/secretvm-verify/amd/vcek/<file> -inform DER -text -noout

# Decode the CRL — see revoked serials and nextUpdate
openssl crl -in ~/.cache/secretvm-verify/amd/crl/Genoa -inform DER -text -noout
```

**Network failure fallback.** If AMD KDS is unreachable or returns an error, the cache falls back to a stale entry rather than failing the verification. Better to verify with a slightly old CRL than to fail every SEV-SNP attestation while KDS is down.

**Force a refresh** (skip the cache for this call, fetch fresh, write back to cache):

CLI:
```sh
python check_vm.py <url> --reload-amd-kds
```

Programmatic — pass `reload_amd_kds=True`:

```python
result = check_sev_cpu_attestation(quote, product="Genoa", reload_amd_kds=True)
result = check_secret_vm(url, reload_amd_kds=True)
result = check_cpu_attestation(quote, product="Genoa", reload_amd_kds=True)
result = check_agent(agent_id, "base", reload_amd_kds=True)

# Async variants accept the same parameter
result = await check_sev_cpu_attestation_async(quote, product="Genoa", reload_amd_kds=True)
result = await check_secret_vm_async(url, reload_amd_kds=True)
```

The `reload_amd_kds` parameter has no effect on Intel TDX verification (TDX doesn't cache; the upstream [`dcap-qvl`](https://pypi.org/project/dcap-qvl/) library manages its own ephemeral state).

**To clear the cache entirely:**

```sh
rm -rf ~/.cache/secretvm-verify/amd
```

## Requirements

- Python >= 3.10
- `requests`, `cryptography`, `PyYAML`, `web3`, [`dcap-qvl`](https://pypi.org/project/dcap-qvl/) (TDX quote verification)

No system-level dependencies. AMD SEV-SNP certificate chains (RSA-PSS) are verified natively via `cryptography`.

## License

MIT
