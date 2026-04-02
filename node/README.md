# secretvm-verify

Attestation verification SDK for confidential computing environments. Verifies Intel TDX, AMD SEV-SNP, and NVIDIA GPU attestation quotes, with end-to-end Secret VM verification that validates CPU attestation, GPU attestation, and the cryptographic bindings between them.

## What it verifies

- **Intel TDX** — Parses a TDX Quote v4, verifies the ECDSA-P256 signature chain (PCK -> Intermediate -> Root), validates QE report binding, and checks TCB status against Intel's Provisioning Certification Service.
- **AMD SEV-SNP** — Parses a SEV-SNP attestation report, fetches the VCEK certificate from AMD's Key Distribution Service, verifies the ECDSA-P384 report signature, and validates the certificate chain (VCEK -> ASK -> ARK).
- **NVIDIA GPU** — Submits GPU attestation evidence to NVIDIA's Remote Attestation Service (NRAS), verifies the returned JWT signatures against NVIDIA's published JWKS keys, and extracts per-GPU attestation claims.
- **SecretVM workload** — Given a TDX or SEV-SNP quote and a `docker-compose.yaml`, determines whether the quote was produced by a known SecretVM image and verifies the exact compose file that was booted.
- **Secret VM** — End-to-end verification that connects to a VM's attestation endpoints, verifies CPU and GPU attestation, and validates TLS and GPU cryptographic bindings.
- **ERC-8004 Agent verification** — End-to-end verification of on-chain AI agents registered under the [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) standard. Resolves agent metadata from any supported blockchain (Ethereum, Base, Arbitrum, Polygon, and 14 more), discovers the agent's TEE attestation endpoints, and runs the full verification flow. Three composable functions:
  - **`resolveAgent`** — Queries the on-chain registry contract for the agent's metadata.
  - **`verifyAgent`** — Takes agent metadata and runs full TEE verification against the agent's declared endpoints.
  - **`checkAgent`** — End-to-end: resolves the agent on-chain, then verifies it.

## Installation

```bash
npm install secretvm-verify
```

## Quick start

### Verify a Secret VM (recommended)

The simplest way to verify a VM — handles CPU detection, GPU detection, and all binding checks automatically.

```typescript
import { checkSecretVm } from 'secretvm-verify';

const result = await checkSecretVm('my-vm.example.com');

console.log(result.valid);           // true if all checks pass
console.log(result.attestationType); // "SECRET-VM"
console.log(result.checks);         // { tls_cert_obtained: true, cpu_attestation_valid: true, ... }
console.log(result.report);         // { tls_fingerprint: "...", cpu: {...}, cpu_type: "TDX", ... }
console.log(result.errors);         // [] if no errors
```

### Verify an ERC-8004 agent

Verify an AI agent registered on-chain using the ERC-8004 standard. Supports 18 chains including Ethereum, Base, Arbitrum, and more.

```typescript
import { checkAgent } from 'secretvm-verify';

// End-to-end: resolve on-chain + verify TEE attestation
const result = await checkAgent(38114, 'base');

console.log(result.valid);           // true if all checks pass
console.log(result.attestationType); // "ERC-8004"
console.log(result.checks);         // { agent_resolved: true, metadata_valid: true, ... }
```

You can also work with the individual steps:

```typescript
import { resolveAgent, verifyAgent } from 'secretvm-verify';

// Step 1: Resolve agent metadata from the blockchain
const metadata = await resolveAgent(38114, 'base');
console.log(metadata.name);            // Agent name
console.log(metadata.services);        // [{ name: "teequote", endpoint: "..." }, ...]
console.log(metadata.supportedTrust);  // ["tee-attestation"]

// Step 2: Verify the agent's TEE attestation
const result = await verifyAgent(metadata);
```

**RPC configuration:** Set `SECRETVM_RPC_BASE` (or `SECRETVM_RPC_<CHAIN>`) environment variable to use your own RPC endpoint. Falls back to public RPCs if not set.

### Resolve SecretVM version from a quote

Given a TDX or SEV-SNP quote, determine which official SecretVM template and version produced it:

```typescript
import { resolveSecretVmVersion } from 'secretvm-verify';
import { readFileSync } from 'fs';

const result = resolveSecretVmVersion(readFileSync('cpu_quote.txt', 'utf8'));
if (result) {
  console.log(result.template_name); // e.g. "small"
  console.log(result.artifacts_ver); // e.g. "v0.0.25"
} else {
  console.log('Not a known SecretVM');
}
```

### Verify a workload (quote + docker-compose)

Verify that a quote was produced by a known SecretVM *and* that it was running a specific `docker-compose.yaml`:

```typescript
import { verifyWorkload, formatWorkloadResult } from 'secretvm-verify';
import { readFileSync } from 'fs';

// Auto-detects TDX vs SEV-SNP:
const result = verifyWorkload(
  readFileSync('cpu_quote.txt', 'utf8'),
  readFileSync('docker-compose.yaml', 'utf8'),
);

console.log(result.status);        // "authentic_match" | "authentic_mismatch" | "not_authentic"
console.log(result.template_name); // e.g. "small"   (undefined when not_authentic)
console.log(result.artifacts_ver); // e.g. "v0.0.25" (undefined when not_authentic)
console.log(result.env);           // e.g. "prod"    (undefined when not_authentic)
console.log(formatWorkloadResult(result)); // human-readable summary
```

### Verify a CPU quote (auto-detect TDX vs SEV-SNP)

All verification functions accept either raw quote data or a VM URL. When a URL is passed, the quote is automatically fetched from the VM's attestation endpoint.

```typescript
import { checkCpuAttestation } from 'secretvm-verify';
import { readFileSync } from 'fs';

// From a file:
const result = await checkCpuAttestation(readFileSync('cpu_quote.txt', 'utf8'));

// Or directly from a VM URL:
const result = await checkCpuAttestation('blue-moose.vm.scrtlabs.com');

console.log(result.attestationType); // "TDX" or "SEV-SNP"
console.log(result.valid);
```

This works with all functions: `checkTdxCpuAttestation`, `checkSevCpuAttestation`, `checkNvidiaGpuAttestation`, `verifyWorkload`, `resolveSecretVmVersion`. When a URL is passed to `verifyWorkload`, both the quote and docker-compose are fetched automatically.

## API reference

### `AttestationResult`

All functions return an `AttestationResult` with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `boolean` | Overall pass/fail |
| `attestationType` | `string` | `"TDX"`, `"SEV-SNP"`, `"NVIDIA-GPU"`, or `"SECRET-VM"` |
| `checks` | `Record<string, boolean>` | Individual verification steps |
| `report` | `Record<string, any>` | Parsed attestation fields |
| `errors` | `string[]` | Error messages for failed checks |

### Functions

#### `checkSecretVm(url, product?)`

End-to-end Secret VM verification. Connects to `<url>:29343`, fetches CPU and GPU quotes, verifies both, and checks TLS and GPU bindings.

**Parameters:**
- `url` — VM address (e.g., `"my-vm.example.com"`, `"https://my-vm:29343"`)
- `product` — AMD product name (`"Genoa"`, `"Milan"`, `"Turin"`). Only needed for SEV-SNP, auto-detected if omitted.

#### `checkCpuAttestation(data, product?)`

Auto-detects Intel TDX vs AMD SEV-SNP and delegates to the appropriate function.

#### `checkTdxCpuAttestation(data)`

Verifies an Intel TDX Quote v4.

#### `checkSevCpuAttestation(data, product?)`

Verifies an AMD SEV-SNP attestation report.

#### `checkNvidiaGpuAttestation(data)`

Verifies NVIDIA GPU attestation via NRAS.

#### `resolveSecretVmVersion(data)`

Looks up a quote in the SecretVM artifact registry. Returns the matching template name and version, or `null` if not found.

#### `verifyWorkload(data, dockerComposeYaml)`

Auto-detects quote type and verifies that it was produced by a known SecretVM running the given docker-compose.

#### `verifyTdxWorkload(data, dockerComposeYaml)`

TDX-specific workload verification.

#### `verifySevWorkload(data, dockerComposeYaml)`

SEV-SNP-specific workload verification.

#### `formatWorkloadResult(result)`

Formats a `WorkloadResult` as a human-readable string.

### `WorkloadResult`

| Field | Type | Description |
|-------|------|-------------|
| `status` | `WorkloadStatus` | `"authentic_match"`, `"authentic_mismatch"`, or `"not_authentic"` |
| `template_name` | `string \| undefined` | SecretVM template (e.g. `"small"`) |
| `artifacts_ver` | `string \| undefined` | Artifacts version (e.g. `"v0.0.25"`) |
| `env` | `string \| undefined` | Environment (e.g. `"prod"`) |

### ERC-8004 Agent Functions

#### `checkAgent(agentId, chain)`

End-to-end ERC-8004 agent verification. Resolves agent metadata from the on-chain registry, then verifies TEE attestation.

**Parameters:**
- `agentId` — The agent's on-chain token ID (number)
- `chain` — Chain name (e.g. `"base"`, `"ethereum"`, `"arbitrum"`)

#### `resolveAgent(agentId, chain)`

Resolves an agent's metadata from the on-chain registry contract. Returns an `AgentMetadata` object.

#### `verifyAgent(metadata)`

Verifies an ERC-8004 agent given its metadata. Discovers teequote/workload endpoints and runs the full verification flow.

**Parameters:**
- `metadata` — `AgentMetadata` object with `name`, `supportedTrust`, and `services`

### `AgentMetadata`

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Agent name |
| `description` | `string \| undefined` | Agent description |
| `supportedTrust` | `string[]` | Trust models (must include `"tee-attestation"`) |
| `services` | `AgentService[]` | Service endpoints (`name` + `endpoint`) |

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

Install globally:

```bash
npm install -g secretvm-verify
```

Or from the repo:

```bash
cd node
npm install && npm run build
npm install -g .
```

Then use from anywhere:

```bash
# Verify a Secret VM (CPU + GPU + TLS binding)
secretvm-verify --secretvm yellow-krill.vm.scrtlabs.com

# Verify individual attestation quotes from files
secretvm-verify --tdx cpu_quote.txt
secretvm-verify --sev amd_cpu_quote.txt --product Genoa
secretvm-verify --gpu gpu_attest.txt

# Auto-detect CPU quote type (TDX vs SEV-SNP)
secretvm-verify --cpu cpu_quote.txt

# Resolve which SecretVM version produced a quote
secretvm-verify --resolve-version cpu_quote.txt
secretvm-verify -rv cpu_quote.txt

# Verify a quote + docker-compose match
secretvm-verify --verify-workload cpu_quote.txt --compose docker-compose.yaml
secretvm-verify -vw cpu_quote.txt --compose docker-compose.yaml

# JSON output (any command)
secretvm-verify --secretvm yellow-krill.vm.scrtlabs.com --raw

# Verbose output (all attestation fields)
secretvm-verify --secretvm yellow-krill.vm.scrtlabs.com -v

# Verify an ERC-8004 agent on-chain
SECRETVM_RPC_BASE="https://..." secretvm-verify --check-agent 38114 --chain base
secretvm-verify --check-agent 38114 --chain base -v

# Verify an agent from a metadata JSON file
secretvm-verify --agent metadata.json

# A bare URL defaults to --secretvm
secretvm-verify yellow-krill.vm.scrtlabs.com
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

- Node.js >= 18 (uses built-in `crypto`, `fetch`)
- `openssl` CLI (required for AMD SEV-SNP certificate chain verification)
- `yaml` (npm dependency, included)

## License

MIT
