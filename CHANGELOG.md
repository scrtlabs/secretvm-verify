# Changelog

All notable changes to `secretvm-verify` (both the Node and Python packages) are documented here.

## [0.6.0] — 2026-04-16

### Breaking

- **Renamed `result.checks` keys.** Any downstream code reading these by name needs to be updated:
  - `tls_cert_obtained` → `tls_cert_fetched`
  - `tls_binding` → `tls_binding_verified`
  - `gpu_attestation_valid` → `gpu_quote_verified`
  - `gpu_binding` → `gpu_binding_verified`
  - `workload_verified` → `workload_binding_verified`
- **Removed `cpu_attestation_valid`.** Use `cpu_quote_verified` instead — it now reports `cpuResult.valid` for both TDX and SEV.
- **Reordered the per-check list** in `--secretvm` and agent output. The canonical order is now: `cpu_quote_fetched`, `tls_cert_fetched`, `cpu_quote_verified`, `tls_binding_verified`, `gpu_*`, `workload_*`, `proof_of_cloud_verified`. Ordering is enforced by an `orderChecks` / `order_checks` helper; unknown keys are appended.

### Added

- **Proof of cloud** — new module that POSTs a raw CPU quote to SCRT Labs' `https://secretai.scrtlabs.com/api/quote-parse` endpoint and reports whether the quote originated on a Secret VM.
  - New SDK functions: `checkProofOfCloud(quote)` (Node), `check_proof_of_cloud(quote)` / `check_proof_of_cloud_async(quote)` (Python).
  - Runs automatically inside `checkSecretVm` / `check_secret_vm` and inside the agent verification flow (`verifyAgent` / `verify_agent`).
  - The Node CLI splices the `proof_of_cloud_verified` check row into `--cpu`, `--tdx`, and `--sev` output via an internal `mergeProofOfCloud` helper.
  - `--verbose` shows a curated `Proof of cloud:` JSON dump (`origin`, `status`, `machine_id`) — the 35 KB `collateral` hex and redundant `quote` fields are stripped.

### Changed

- **CLI output rewrite** (`secretvm-verify` Node CLI and `python check_vm.py`):
  - Opening line is now `Verifying <machine>` (was `Checking attestation for <machine> ...`).
  - Footer is now `✅ All Passed` / `🚫 Failed` (was `PASSED` / `FAILED`).
  - Dropped the redundant `✅ Attestation verified: PASS` banner that appeared after the opening line.
  - In `--verbose`, parsed quotes render as JSON under `CPU quote:` and `GPU quote:` (previously a hand-rolled list of `Report data: ...`, `MR TD: ...`, `RTMR0: ...` lines).
  - Default output for all CLI verbs is the check list + verdict only. No TCB / MRTD / RTMR / GPU detail without `--verbose`.

### Tests

- Node: new `checkProofOfCloud` unit tests covering success, `proof_of_cloud=false`, HTTP 500, network error, and request-body shape. Test count: 53 → 58.
- Python: new `test_proof_of_cloud_failure` and `proof_of_cloud_verified` assertions added to the existing SecretVM tests. Test count: 60 → 61.
