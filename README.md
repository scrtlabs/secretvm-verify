# secretvm-verify

Attestation verification SDK for confidential computing environments. Verifies Intel TDX, AMD SEV-SNP, and NVIDIA GPU attestation quotes, with end-to-end Secret VM verification that validates CPU attestation, GPU attestation, and the cryptographic bindings between them.

Available as both a **Python** (PyPI) and **Node.js** (npm) package.

## What it verifies

- **Intel TDX** — Parses a TDX Quote v4, verifies the ECDSA-P256 signature chain (PCK → Intermediate → Root), validates QE report binding, and checks TCB status against Intel's Provisioning Certification Service.
- **AMD SEV-SNP** — Parses a SEV-SNP attestation report, fetches the VCEK certificate from AMD's Key Distribution Service, verifies the ECDSA-P384 report signature, and validates the certificate chain (VCEK → ASK → ARK).
- **NVIDIA GPU** — Submits GPU attestation evidence to NVIDIA's Remote Attestation Service (NRAS), verifies the returned JWT signatures against NVIDIA's published JWKS keys, and extracts per-GPU attestation claims.
- **SecretVM workload** — Given a TDX quote and a `docker-compose.yaml`, determines whether the quote was produced by a known SecretVM image (`resolveSecretVmVersion` / `verifyTdxWorkload`). Looks up the quote's MRTD and RTMR0–2 in a signed registry of official SecretVM builds, then replays the RTMR3 measurement to verify the exact compose file that was booted.
- **Secret VM** — End-to-end verification that connects to a VM's attestation endpoints, verifies CPU and GPU attestation, and validates two critical bindings:
  - **TLS binding**: The first 32 bytes of the CPU quote's `report_data` must match the SHA-256 fingerprint of the VM's TLS certificate, proving the quote was generated on the machine serving that certificate.
  - **GPU binding**: The second 32 bytes of `report_data` must match the GPU attestation nonce, proving the CPU and GPU attestations are linked.

## Installation

### Python

```bash
pip install secretvm-verify
```

### Node.js

```bash
npm install secretvm-verify
```

## Quick start

### Verify a Secret VM (recommended)

The simplest way to verify a VM — handles CPU detection, GPU detection, and all binding checks automatically.

**Python:**

```python
from secretvm.verify import check_secret_vm

result = check_secret_vm("my-vm.example.com")

print(result.valid)           # True if all checks pass
print(result.attestation_type) # "SECRET-VM"
print(result.checks)          # {"tls_cert_obtained": True, "cpu_attestation_valid": True, ...}
print(result.report)          # {"tls_fingerprint": "...", "cpu": {...}, "cpu_type": "TDX", ...}
print(result.errors)          # [] if no errors
```

**Node.js / TypeScript:**

```typescript
import { checkSecretVm } from 'secretvm-verify';

const result = await checkSecretVm('my-vm.example.com');

console.log(result.valid);           // true if all checks pass
console.log(result.attestationType); // "SECRET-VM"
console.log(result.checks);         // { tls_cert_obtained: true, cpu_attestation_valid: true, ... }
console.log(result.report);         // { tls_fingerprint: "...", cpu: {...}, cpu_type: "TDX", ... }
console.log(result.errors);         // [] if no errors
```

### Resolve SecretVM version from a TDX quote

Given a TDX quote, determine which official SecretVM template and version produced it:

**Python:**

```python
from secretvm.verify import resolve_secretvm_version

result = resolve_secretvm_version(open("cpu_quote.txt").read())
if result:
    print(result["template_name"])  # e.g. "small"
    print(result["artifacts_ver"])  # e.g. "v0.0.25"
else:
    print("Not a known SecretVM")
```

**Node.js / TypeScript:**

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

### Verify a TDX workload (quote + docker-compose)

Verify that a TDX quote was produced by a known SecretVM *and* that it was running a specific `docker-compose.yaml`:

**Python:**

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

*If you know the quote type, you can call `verify_tdx_workload` directly (same signature).*

**Node.js / TypeScript:**

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

*If you know the quote type, you can call `verifyTdxWorkload` directly (same signature).*

**Status values:**

| Status | Meaning |
|--------|---------|
| `authentic_match` | Quote is from a known SecretVM **and** the compose file matches exactly |
| `authentic_mismatch` | Quote is from a known SecretVM but the compose file does **not** match |
| `not_authentic` | Quote's MRTD/RTMR values are not in the SecretVM registry |

### Verify a CPU quote (auto-detect TDX vs SEV-SNP)

If you have a raw CPU attestation quote and want to verify it directly:

**Python:**

```python
from secretvm.verify import check_cpu_attestation

# Automatically detects whether the quote is Intel TDX (hex) or AMD SEV-SNP (base64)
result = check_cpu_attestation(open("cpu_quote.txt").read())

print(result.attestation_type)  # "TDX" or "SEV-SNP"
print(result.valid)
```

**Node.js:**

```typescript
import { checkCpuAttestation } from 'secretvm-verify';
import { readFileSync } from 'fs';

const result = await checkCpuAttestation(readFileSync('cpu_quote.txt', 'utf8'));

console.log(result.attestationType); // "TDX" or "SEV-SNP"
console.log(result.valid);
```

## API reference

### `AttestationResult`

All functions return an `AttestationResult` with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `valid` | `bool` / `boolean` | Overall pass/fail |
| `attestation_type` / `attestationType` | `str` / `string` | `"TDX"`, `"SEV-SNP"`, `"NVIDIA-GPU"`, or `"SECRET-VM"` |
| `checks` | `dict` / `Record<string, boolean>` | Individual verification steps |
| `report` | `dict` / `Record<string, any>` | Parsed attestation fields |
| `errors` | `list` / `string[]` | Error messages for failed checks |

### Functions

#### `check_secret_vm(url, product="")` / `checkSecretVm(url, product?)`

End-to-end Secret VM verification. Connects to `<url>:29343`, fetches CPU and GPU quotes, verifies both, and checks TLS and GPU bindings.

**Parameters:**
- `url` — VM address (e.g., `"my-vm.example.com"`, `"https://my-vm:29343"`)
- `product` — AMD product name (`"Genoa"`, `"Milan"`, `"Turin"`). Only needed for SEV-SNP, auto-detected if omitted.

**Checks performed:**
| Check | Description |
|-------|-------------|
| `tls_cert_obtained` | TLS certificate retrieved from the VM |
| `cpu_quote_fetched` | CPU quote fetched from `/cpu` endpoint |
| `cpu_attestation_valid` | CPU attestation signature chain verified |
| `tls_binding` | report_data first half matches TLS cert fingerprint |
| `gpu_quote_fetched` | GPU quote fetched from `/gpu` endpoint (false if no GPU) |
| `gpu_attestation_valid` | GPU attestation verified via NVIDIA NRAS (only if GPU present) |
| `gpu_binding` | report_data second half matches GPU nonce (only if GPU present) |

---

#### `check_cpu_attestation(data, product="")` / `checkCpuAttestation(data, product?)`

Auto-detects Intel TDX vs AMD SEV-SNP and delegates to the appropriate function.

**Parameters:**
- `data` — Raw quote text (hex-encoded for TDX, base64-encoded for SEV-SNP)
- `product` — AMD product name (only used for SEV-SNP)

---

#### `check_tdx_cpu_attestation(data)` / `checkTdxCpuAttestation(data)`

Verifies an Intel TDX Quote v4.

**Parameters:**
- `data` — Hex-encoded TDX quote

**Report fields include:** `version`, `mr_td`, `mr_seam`, `rt_mr0`–`rt_mr3`, `report_data`, `fmspc`, `tcb_status`

---

#### `check_amd_cpu_attestation(data, product="")` / `checkAmdCpuAttestation(data, product?)`

Verifies an AMD SEV-SNP attestation report.

**Parameters:**
- `data` — Base64-encoded SEV-SNP report
- `product` — `"Genoa"`, `"Milan"`, or `"Turin"`. Auto-detected if omitted.

**Report fields include:** `version`, `measurement`, `report_data`, `chip_id`, `vmpl`, `policy`, `debug_allowed`, `product`

---

#### `resolve_secretvm_version(data)` / `resolveSecretVmVersion(data)`

Looks up a TDX quote in the SecretVM artifact registry. Returns the matching template name and version, or `None` / `null` if the quote does not match any known SecretVM build.

**Parameters:**
- `data` — Hex-encoded TDX quote

**Returns:** `{ template_name, artifacts_ver }` or `None` / `null`

---

#### `verify_tdx_workload(data, docker_compose_yaml)` / `verifyTdxWorkload(data, dockerComposeYaml)`

Verifies that a TDX quote was produced by a known SecretVM running a specific `docker-compose.yaml`. Replays the RTMR3 measurement from the compose content and compares it to the value in the quote.

**Parameters:**
- `data` — Hex-encoded TDX quote
- `docker_compose_yaml` / `dockerComposeYaml` — Contents of the `docker-compose.yaml` file

**Returns:** `WorkloadResult`

---

#### `verify_sev_workload(data, docker_compose_yaml)` / `verifySevWorkload(data, dockerComposeYaml)`

**TODO — not yet implemented.** Always returns `not_authentic`. SEV-SNP workload verification will be added in a future release once a SEV artifact registry and measurement replay logic are available.

---

#### `verify_workload(data, docker_compose_yaml)` / `verifyWorkload(data, dockerComposeYaml)`

Generic workload verifier that auto-detects the quote type and delegates to the appropriate lower-level function:

- **TDX** (hex) → `verify_tdx_workload` / `verifyTdxWorkload`
- **SEV-SNP** (base64) → `verify_sev_workload` / `verifySevWorkload` *(TODO — currently returns `not_authentic`)*
- **Unknown** → returns `not_authentic`

**Parameters:**
- `data` — Hex-encoded TDX quote **or** base64-encoded SEV-SNP report
- `docker_compose_yaml` / `dockerComposeYaml` — Contents of the `docker-compose.yaml` file

**Returns:** `WorkloadResult`

---

#### `format_workload_result(result)` / `formatWorkloadResult(result)`

Formats a `WorkloadResult` as a short, human-readable string with status emoji.

**Example output:**

```
✅ Confirmed an authentic SecretVM (TDX), vm_type small, artifacts v0.0.25, environment prod
✅ Confirmed that the VM is running the specified docker-compose.yaml
```

```
✅ Confirmed an authentic SecretVM (TDX), vm_type small, artifacts v0.0.25, environment prod
🚫 Attestation does not match the specified docker-compose.yaml
```

```
🚫 Attestation doesn't belong to an authentic SecretVM
```

---

#### `WorkloadResult`

Python dataclass / TypeScript interface returned by workload functions:

| Field | Type | Description |
|-------|------|-------------|
| `status` | `WorkloadStatus` | `"authentic_match"`, `"authentic_mismatch"`, or `"not_authentic"` |
| `template_name` | `str \| None` / `string \| undefined` | SecretVM template (e.g. `"small"`), set when status ≠ `not_authentic` |
| `artifacts_ver` | `str \| None` / `string \| undefined` | Artifacts version (e.g. `"v0.0.25"`), set when status ≠ `not_authentic` |
| `env` | `str \| None` / `string \| undefined` | Environment (e.g. `"prod"`), set when status ≠ `not_authentic` |

---

#### `check_nvidia_gpu_attestation(data)` / `checkNvidiaGpuAttestation(data)`

Verifies NVIDIA GPU attestation via NRAS.

**Parameters:**
- `data` — JSON attestation payload

**Report fields include:** `overall_result`, `gpus` (per-GPU model, driver version, secure boot status, measurement results)

## CLI usage

### Node.js CLI

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

# Resolve which SecretVM version produced a TDX quote
secretvm-verify --resolve-version cpu_quote.txt
# → Template: small, Version: v0.0.25

# Verify a TDX quote + docker-compose match
secretvm-verify --verify-workload cpu_quote.txt --compose docker-compose.yaml
# → ✅ Confirmed an authentic SecretVM (TDX), vm_type small, artifacts v0.0.25, environment prod
# → ✅ Confirmed that the VM is running the specified docker-compose.yaml

# JSON output (any command)
secretvm-verify --secretvm yellow-krill.vm.scrtlabs.com --raw
secretvm-verify --verify-workload cpu_quote.txt --compose docker-compose.yaml --raw

# A bare URL defaults to --secretvm
secretvm-verify yellow-krill.vm.scrtlabs.com
```

Full usage:

```
Usage: secretvm-verify <command> <value> [--product NAME] [--raw]

Commands:
  --secretvm <url>                        Verify a Secret VM (CPU + GPU + TLS binding)
  --cpu <file>                            Verify a CPU quote (auto-detect TDX vs SEV-SNP)
  --tdx <file>                            Verify an Intel TDX quote
  --sev <file>                            Verify an AMD SEV-SNP report
  --gpu <file>                            Verify an NVIDIA GPU attestation
  --resolve-version <file>                Resolve SecretVM version from a TDX quote
  --verify-workload <file> --compose <file>
                                          Verify TDX workload against a docker-compose.yaml

Options:
  --product NAME       AMD product name (Genoa, Milan, Turin)
  --compose <file>     docker-compose.yaml file (required with --verify-workload)
  --raw                Output raw JSON result
```

### Python CLI

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

## Project structure

```
secretvm-verify/
  python/                     # PyPI package
    pyproject.toml
    src/secretvm/verify/
      __init__.py             # All library code
    tests/
      test_attestation.py     # 49 tests (integration + mocked; includes workload tests)
    check_vm.py               # CLI tool
  node/                       # npm package
    package.json
    tsconfig.json
    src/
      index.ts                # Public exports
      types.ts                # AttestationResult interface
      tdx.ts                  # Intel TDX verification
      amd.ts                  # AMD SEV-SNP verification
      nvidia.ts               # NVIDIA GPU verification
      cpu.ts                  # Auto-detect TDX vs SEV-SNP
      vm.ts                   # End-to-end Secret VM verification
      workload.ts             # resolveSecretVmVersion + verifyTdxWorkload
      artifacts.ts            # SecretVM artifact registry loader
      rtmr.ts                 # RTMR3 replay from docker-compose
      cli.ts                  # CLI tool
      workload.test.ts        # Tests for workload / version resolution
  test-data/                  # Shared attestation quote fixtures
    cpu_quote.txt             # Intel TDX quote (hex)
    amd_cpu_quote.txt         # AMD SEV-SNP report (base64)
    gpu_attest.txt            # NVIDIA GPU attestation (JSON)
    tdx_cpu_docker_check_quote.txt     # TDX quote from a SecretVM with docker-compose
    tdx_cpu_docker_check_compose.yaml  # Matching docker-compose.yaml for the quote above
```

## Requirements

- **Python:** >= 3.10, `requests`, `cryptography`, `openssl` CLI
- **Node.js:** >= 18 (uses built-in `crypto`, `fetch`), `openssl` CLI

The `openssl` CLI is required for AMD SEV-SNP certificate chain verification (AMD's certificates use RSA-PSS with non-standard ASN.1 encoding that some library parsers reject).

## License

MIT
