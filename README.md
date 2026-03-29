# secretvm-attestation

Attestation verification SDK for confidential computing environments. Verifies Intel TDX, AMD SEV-SNP, and NVIDIA GPU attestation quotes, with end-to-end Secret VM verification that validates CPU attestation, GPU attestation, and the cryptographic bindings between them.

Available as both a **Python** (PyPI) and **Node.js** (npm) package.

## What it verifies

- **Intel TDX** — Parses a TDX Quote v4, verifies the ECDSA-P256 signature chain (PCK → Intermediate → Root), validates QE report binding, and checks TCB status against Intel's Provisioning Certification Service.
- **AMD SEV-SNP** — Parses a SEV-SNP attestation report, fetches the VCEK certificate from AMD's Key Distribution Service, verifies the ECDSA-P384 report signature, and validates the certificate chain (VCEK → ASK → ARK).
- **NVIDIA GPU** — Submits GPU attestation evidence to NVIDIA's Remote Attestation Service (NRAS), verifies the returned JWT signatures against NVIDIA's published JWKS keys, and extracts per-GPU attestation claims.
- **Secret VM** — End-to-end verification that connects to a VM's attestation endpoints, verifies CPU and GPU attestation, and validates two critical bindings:
  - **TLS binding**: The first 32 bytes of the CPU quote's `report_data` must match the SHA-256 fingerprint of the VM's TLS certificate, proving the quote was generated on the machine serving that certificate.
  - **GPU binding**: The second 32 bytes of `report_data` must match the GPU attestation nonce, proving the CPU and GPU attestations are linked.

## Installation

### Python

```bash
pip install secretvm-attestation
```

### Node.js

```bash
npm install secretvm-attestation
```

## Quick start

### Verify a Secret VM (recommended)

The simplest way to verify a VM — handles CPU detection, GPU detection, and all binding checks automatically.

**Python:**

```python
from secretai.attestation import check_secret_vm

result = check_secret_vm("my-vm.example.com")

print(result.valid)           # True if all checks pass
print(result.attestation_type) # "SECRET-VM"
print(result.checks)          # {"tls_cert_obtained": True, "cpu_attestation_valid": True, ...}
print(result.report)          # {"tls_fingerprint": "...", "cpu": {...}, "cpu_type": "TDX", ...}
print(result.errors)          # [] if no errors
```

**Node.js / TypeScript:**

```typescript
import { checkSecretVm } from 'secretvm-attestation';

const result = await checkSecretVm('my-vm.example.com');

console.log(result.valid);           // true if all checks pass
console.log(result.attestationType); // "SECRET-VM"
console.log(result.checks);         // { tls_cert_obtained: true, cpu_attestation_valid: true, ... }
console.log(result.report);         // { tls_fingerprint: "...", cpu: {...}, cpu_type: "TDX", ... }
console.log(result.errors);         // [] if no errors
```

### Verify a CPU quote (auto-detect TDX vs SEV-SNP)

If you have a raw CPU attestation quote and want to verify it directly:

**Python:**

```python
from secretai.attestation import check_cpu_attestation

# Automatically detects whether the quote is Intel TDX (hex) or AMD SEV-SNP (base64)
result = check_cpu_attestation(open("cpu_quote.txt").read())

print(result.attestation_type)  # "TDX" or "SEV-SNP"
print(result.valid)
```

**Node.js:**

```typescript
import { checkCpuAttestation } from 'secretvm-attestation';
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

#### `check_nvidia_gpu_attestation(data)` / `checkNvidiaGpuAttestation(data)`

Verifies NVIDIA GPU attestation via NRAS.

**Parameters:**
- `data` — JSON attestation payload

**Report fields include:** `overall_result`, `gpus` (per-GPU model, driver version, secure boot status, measurement results)

## CLI usage

### Python

```bash
cd python
pip install -e .
python check_vm.py https://my-vm:29343
python check_vm.py https://my-vm:29343 --raw     # JSON output
python check_vm.py https://my-vm:29343 --product Genoa
```

### Node.js

```bash
cd node
npm install && npm run build
node dist/cli.js https://my-vm:29343
node dist/cli.js https://my-vm:29343 --raw        # JSON output
node dist/cli.js https://my-vm:29343 --product Genoa
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
secretvm-attestation/
  python/                     # PyPI package
    pyproject.toml
    src/secretai/attestation/
      __init__.py             # All library code
    tests/
      test_attestation.py     # 34 tests (integration + mocked)
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
      cli.ts                  # CLI tool
  test-data/                  # Shared attestation quote fixtures
    cpu_quote.txt             # Intel TDX quote (hex)
    amd_cpu_quote.txt         # AMD SEV-SNP report (base64)
    gpu_attest.txt            # NVIDIA GPU attestation (JSON)
```

## Requirements

- **Python:** >= 3.10, `requests`, `cryptography`, `openssl` CLI
- **Node.js:** >= 18 (uses built-in `crypto`, `fetch`), `openssl` CLI

The `openssl` CLI is required for AMD SEV-SNP certificate chain verification (AMD's certificates use RSA-PSS with non-standard ASN.1 encoding that some library parsers reject).

## License

MIT
