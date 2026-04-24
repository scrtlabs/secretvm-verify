# secretvm-verify

Attestation verification SDK for confidential computing environments. Verifies Intel TDX, AMD SEV-SNP, and NVIDIA GPU attestation quotes, with end-to-end Secret VM verification that validates CPU attestation, GPU attestation, and the cryptographic bindings between them.

## What it verifies

- **Intel TDX** — Performs full Intel DCAP quote verification, delegating the cryptographic checks to the upstream [`@teekit/qvl`](https://www.npmjs.com/package/@teekit/qvl) library. Verifies the PCK certificate chain against a pinned Intel SGX Root CA, the QE Identity, PCK CRL and Root CA CRL revocation, the TCB Info signature, the TCB status, the quote signature, and the QE report binding. Collateral (TCB Info, QE Identity, CRLs, issuer chains) is fetched from a Provisioning Certificate Caching Service (PCCS) — defaults to SCRT Labs' deployment.
- **AMD SEV-SNP** — Parses a SEV-SNP attestation report, fetches the VCEK certificate from AMD's Key Distribution Service, verifies the ECDSA-P384 report signature, and validates the certificate chain (VCEK -> ASK -> ARK).
- **NVIDIA GPU** — Submits GPU attestation evidence to NVIDIA's Remote Attestation Service (NRAS), verifies the returned JWT signatures against NVIDIA's published JWKS keys, and extracts per-GPU attestation claims.
- **SecretVM workload** — Given a TDX or SEV-SNP quote and a `docker-compose.yaml`, determines whether the quote was produced by a known SecretVM image and verifies the exact compose file that was booted.
- **Secret VM** — End-to-end verification that connects to a VM's attestation endpoints, verifies CPU and GPU attestation, and validates TLS and GPU cryptographic bindings.
- **Proof of cloud** — POSTs a CPU quote to SCRT Labs' [`/api/quote-parse`](https://secretai.scrtlabs.com/api/quote-parse) endpoint, which confirms the quote originated on a Secret VM and returns its `origin` and `machine_id`. Opt-in: pass `checkProofOfCloud=true` to `checkSecretVm` / `checkAgent` / `verifyAgent`, or use `--proof-of-cloud` on the CLI. A standalone `checkProofOfCloud` function is also exposed.
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
console.log(result.checks);         // { cpu_quote_fetched: true, tls_cert_fetched: true, ... }
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

#### `checkSecretVm(url, product?, reloadAmdKds?, checkProofOfCloud?)`

End-to-end Secret VM verification. Connects to `<url>:29343`, fetches CPU and GPU quotes, verifies both, and checks TLS and GPU bindings.

**Parameters:**
- `url` — VM address (e.g., `"my-vm.example.com"`, `"https://my-vm:29343"`)
- `product` — AMD product name (`"Genoa"`, `"Milan"`, `"Turin"`). Only needed for SEV-SNP, auto-detected if omitted.
- `reloadAmdKds` — If `true`, bypass the AMD KDS cache (no effect on TDX).
- `checkProofOfCloud` — If `true`, also POST the quote to SCRT Labs' `/api/quote-parse` endpoint. Opt-in; off by default.

The returned `result.report.docker_compose` contains the raw docker-compose the VM served (useful for inspecting what was measured).

#### `checkCpuAttestation(data, product?)`

Auto-detects Intel TDX vs AMD SEV-SNP and delegates to the appropriate function.

#### `checkTdxCpuAttestation(data)`

Verifies an Intel TDX Quote v4.

#### `checkSevCpuAttestation(data, product?)`

Verifies an AMD SEV-SNP attestation report.

#### `checkNvidiaGpuAttestation(data)`

Verifies NVIDIA GPU attestation via NRAS.

#### `checkProofOfCloud(quote)`

POSTs a raw CPU quote to SCRT Labs' [`/api/quote-parse`](https://secretai.scrtlabs.com/api/quote-parse) endpoint. Returns an `AttestationResult` with `attestationType: "PROOF-OF-CLOUD"` and a single check `proof_of_cloud_verified`. The report exposes `origin`, `proof_of_cloud`, `status`, and `machine_id`. `checkSecretVm` and `verifyAgent` accept an optional `checkProofOfCloud` flag (off by default) that folds this verdict into their check list; the CLI exposes it as `--proof-of-cloud`.

#### `resolveSecretVmVersion(data)`

Looks up a quote in the SecretVM artifact registry. Returns the matching template name and version, or `null` if not found.

#### `verifyWorkload(data, dockerComposeYaml, dockerFilesInput?)`

Auto-detects quote type and verifies that it was produced by a known SecretVM running the given docker-compose. The optional third argument `{ dockerFiles?, dockerFilesSha256? }` supports TDX VMs that bake a Dockerfiles archive into the image — pass the raw tar bytes (they get SHA-256'd client-side) or a precomputed hex digest. SEV-SNP ignores it.

#### `verifyTdxWorkload(data, dockerComposeYaml, dockerFilesInput?)`

TDX-specific workload verification. Same optional `{ dockerFiles?, dockerFilesSha256? }` argument as `verifyWorkload`; when provided, the SHA-256 of the archive is appended to the RTMR3 replay as `log[2]`.

#### `verifySevWorkload(data, dockerComposeYaml, dockerFilesInput?)`

SEV-SNP-specific workload verification. When `dockerFiles` bytes or `dockerFilesSha256` hex is supplied, the digest is appended to the kernel cmdline as `docker_additional_files_hash=<hex>` before the SEV-SNP GCTX launch measurement is recomputed.

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
secretvm-verify --secretvm yellow-krill.vm.scrtlabs.com --json   # minimal JSON
secretvm-verify --secretvm yellow-krill.vm.scrtlabs.com --raw    # full JSON with parsed report

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
| [SCRT PCCS](https://pccs.scrtlabs.com) | TDX | DCAP collateral (TCB Info, QE Identity, PCK CRL, Root CA CRL, issuer chains) |
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
secretvm-verify --secretvm <url> --reload-amd-kds
secretvm-verify --sev <quote.txt> --product Genoa --reload-amd-kds
```

Programmatic — pass `true` as the third argument:

```js
const result = await checkSevCpuAttestation(quote, "Genoa", /* reloadAmdKds */ true);
const result = await checkSecretVm(url, "", /* reloadAmdKds */ true);
const result = await checkCpuAttestation(quote, "Genoa", /* reloadAmdKds */ true);
const result = await checkAgent(agentId, "base", /* reloadAmdKds */ true);
```

The `--reload-amd-kds` flag has no effect on Intel TDX verification (TDX doesn't cache; the upstream `@teekit/qvl` library manages its own ephemeral state).

**To clear the cache entirely:**

```sh
rm -rf ~/.cache/secretvm-verify/amd
```

## Requirements

- Node.js >= 18 (uses built-in `crypto`, `fetch`)
- npm dependencies: [`@teekit/qvl`](https://www.npmjs.com/package/@teekit/qvl) (TDX quote verification), [`asn1js`](https://www.npmjs.com/package/asn1js) (parses the CRL's `nextUpdate` field for cache TTL), `ethers` (ERC-8004 agent resolution) — installed automatically.

No system-level dependencies. AMD SEV-SNP certificate chains (RSA-PSS) are verified natively via `node:crypto`.

## License

MIT
