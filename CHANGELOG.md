# Changelog

All notable changes to `secretvm-verify` (both the Node and Python packages) are documented here.

## [0.9.0] — 2026-04-27

### Added

- **`SECRETVM_PCCS_URL` environment variable** — overrides the PCCS server used to fetch Intel TDX collateral (TCB Info, QE Identity, CRLs). Defaults to `https://pccs.scrtlabs.com`. Useful for self-hosted PCCS deployments or to point directly at Intel's PCS (`https://api.trustedservices.intel.com`). Honoured by both the Node and Python packages.
- **Strict mode (`--strict` / `strict=True`)** — disables the stale-cache fallback when AMD KDS is unreachable, rate-limited (429), or returns a non-200. Trades availability for freshness: in strict mode, a stale cached VCEK / cert chain / CRL no longer rescues a failed live fetch, so a recently revoked VCEK can't slip through. Default is permissive (current behaviour). Available on `checkSecretVm`, `checkCpuAttestation`, `checkSevCpuAttestation`, `checkAgent`, `verifyAgent` (Node and Python, sync and async) and as a CLI flag on both `secretvm-verify` (Node) and `python check_vm.py`.

### Security

- **AMD ARK is now pinned** per product (Milan, Genoa, Turin) by SHA-256 of its SubjectPublicKeyInfo. Previously the AMD cert chain check (VCEK → ASK → ARK) verified the ARK was self-signed but didn't tie it to AMD — a DNS-spoof or compromised AMD KDS could substitute a self-signed impostor ARK and the chain would still pass. The fix anchors the chain in code, so trust no longer depends on TLS to `kdsintf.amd.com`. Applies to both the Node and Python packages.
- **AMD policy is now enforced.** Two new check rows on the SEV-SNP path, both required for `valid=true`:
  - **`debug_disabled`** — fails if the report has `debug_allowed=true`. A debug-mode VM exposes secrets; SecretVM should never trust one.
  - **`tcb_ordering_valid`** — fails if `current_tcb >= committed_tcb >= launch_tcb` is violated componentwise (per the SEV-SNP firmware ABI; an inversion indicates a firmware downgrade or a malformed report).
- **TDX `debug_disabled` made explicit.** Same key now appears on the TDX path's per-check breakdown (parses bit 0 of `td_attributes` — the TUD/DEBUG flag). `dcap-qvl` already rejects debug-mode TDX quotes inside its `verify()`; surfacing the check explicitly mirrors the SEV-SNP shape and makes the policy visible in the output.
- **AMD CRL signature is now verified.** New `crl_signature_valid` check on the SEV-SNP path, required for `valid=true`. Previously the verifier parsed the CRL and consulted the revoked-serial list but never confirmed the CRL itself was signed by AMD — a forged CRL with revocations stripped would slip through. The fix verifies the CRL's `tbsCertList` signature against the pinned ARK public key (RSA-PSS-SHA384, salt 48), as AMD KDS specifies. Applies to both the Node and Python packages.
- **VCEK extensions are now checked against the report.** New `vcek_matches_report` check on the SEV-SNP path, required for `valid=true`. Previously we built the AMD KDS URL from the report's `chip_id` and `reported_tcb` and trusted KDS to return the matching cert. The fix parses the VCEK's custom OID extensions (HWID `1.3.6.1.4.1.3704.1.4`; TCB components `1.3.6.1.4.1.3704.1.3.{1,2,3,8}`) and compares them byte-for-byte to the report. Defends against a misbehaving KDS, a bug in URL construction, or any path that yields a real-but-wrong VCEK.
- **AMD verification hardening:**
  - Node's VCEK extension extraction now walks the cert structurally (asn1js: outer SEQUENCE → tbsCertificate → `[3]` extensions list, match by OID string) instead of `indexOf`-ing the OID byte sequence in the raw DER. Removes any chance of a false positive from an OID-shaped byte run inside a serial number or signature value.
  - `vcekMatchesReport` is now wrapped in `try/catch` so a malformed cached or corrupt VCEK fails closed (`valid=false`) instead of throwing.
  - The AMD CRL signature check now also confirms the CRL's issuer Name equals the ARK's subject Name. The signature check already ties the CRL bytes to the ARK key; the Name check removes any residual ambiguity about which CA the CRL is for. Applies to both Node and Python.

### Changed

- **Node TDX verification now uses [`@phala/dcap-qvl`](https://www.npmjs.com/package/@phala/dcap-qvl)** in place of `@teekit/qvl`. The new library is a pure-JS port of the Phala Network Rust crate that the Python package already uses, so both packages now share verification semantics. Closes several gaps in the previous Node path (none affect Python — Python was already on the Rust crate):
  - **TCB Info signature verification** — chain to the pinned Intel SGX Root CA + ECDSA verification of `tcb_info_signature` over canonical TCB JSON. Previously the Node path trusted PCCS over TLS only.
  - **QE Identity signature + content verification** — MRSIGNER, ISVPRODID, masked ATTRIBUTES / MISCSELECT, ISVSVN tier. (Note: this actually closes a pre-existing gap on **both** paths — the Rust crate populates QE Identity collateral but `verify()` doesn't consume it; the JS port does.)
  - **PCK CRL revocation check** — leaf serial is consulted against the PCK CRL.
  - **TD attribute hygiene** — debug bit, reserved bits, SEPT_VE_DISABLE, PKS, KL flags are enforced (`validateTd10` / `validateTd15`).
- **`@teekit/qvl` removed.** The two AMD CRL helpers (`parseCrlRevokedSerials`, `normalizeSerialHex`) are now provided inline using `@phala/dcap-qvl/utils.CertificateList` for DER parsing.
- **TCB-status acceptance widened.** Previously the Node path rejected any status other than `UpToDate` / `ConfigurationNeeded`. The new library (matching the Python path) accepts everything except `Revoked` / `Unknown`. The status string is still surfaced in `result.report.tcb_status` so callers can apply stricter policy if needed.

### Caveat

- Neither library currently signature-verifies the PCK / Root CA CRLs (only `nextUpdate` and serial membership). Trust on CRL contents still rests on TLS to PCCS. Tracked upstream.

## [0.8.4] — 2026-04-25

### Changed

- CLI help examples now use a generic `my-vm.example.com` placeholder instead of real `*.vm.scrtlabs.com` hostnames.

## [0.8.3] — 2026-04-24

### Changed

- CLI help text polish: `--product` marked as optional (auto-detected); `--proof-of-cloud` description shortened to "Verify if the machine is registered with ProofOfCloud alliance. Optional".

## [0.8.2] — 2026-04-24

### Added

- **`--docker-files` / `--docker-files-sha256` now work with `--secretvm`**, not just `--verify-workload`. The flags thread through `checkSecretVm` / `check_secret_vm` (plus async and bare-URL fallback) so a full VM verification against an image baked with Dockerfiles passes end-to-end.
- **`--version` / `-V` flag** — prints `secretvm-verify <version>` and exits. Available on both the Node CLI and `python check_vm.py`.

## [0.8.1] — 2026-04-24

### Breaking

- **Proof-of-cloud is now opt-in.** `checkSecretVm` / `check_secret_vm`, `verifyAgent` / `verify_agent`, and `checkAgent` / `check_agent` no longer run the SCRT Labs quote-parse check by default. Pass `checkProofOfCloud=true` / `check_proof_of_cloud=True` (or `--proof-of-cloud` on the CLI) to include it. The `proof_of_cloud_verified` check row and `result.report.proof_of_cloud` only appear when opted in.

### Added

- **`--show-compose` flag** — prints the `docker-compose.yaml` that was verified after the check list. Works with `--secretvm`, `--verify-workload`, `--check-agent`, `--agent`.
- **`--compose <file | --vm url>` standalone verb** — fetches (or reads) a docker-compose and prints it to stdout, with no verification. Useful for piping (`secretvm-verify --compose --vm <host> > compose.yaml`).
- **`result.report.docker_compose`** — the raw compose string is now attached to the result of `checkSecretVm` / `check_secret_vm` and `verifyAgent` / `verify_agent`, so SDK consumers can inspect the workload that was measured.
- **`DockerFilesInput`** type is now re-exported from the Node package entry point.
- Help text now shows `-rv` and `-vw` as explicit shorthand for `--resolve-version` and `--verify-workload`.

## [0.8.0] — 2026-04-22

### Added

- **Docker-files verification for AMD SEV-SNP** workloads (TDX already shipped in v0.7.0). A SecretVM booted with a Dockerfiles archive baked into its image appends `docker_additional_files_hash=<sha>` to the kernel cmdline; the cmdline is hashed into the SEV-SNP GCTX launch measurement via the hash page. The verifier now reconstructs that cmdline when the digest is provided.
  - SDK: `verifySevWorkload` / `verify_sev_workload` and the auto-detect `verifyWorkload` / `verify_workload` accept the same `{ dockerFiles?, dockerFilesSha256? }` / `docker_files=` / `docker_files_sha256=` inputs as the TDX variants.
  - CLI: `--docker-files` / `--docker-files-sha256` now work for both TDX and SEV-SNP quotes. Help text and README updated accordingly.
  - Source: the guest-side `init-sev` in `scrtlabs/secret-vm-build` reads `docker_additional_files_hash` from `/proc/cmdline` at boot; see `meta-secret-vm/recipes-core/images/secret-vm-initramfs-files/init-sev:47`.

### Caveat

- The exact position of `docker_additional_files_hash` in the kernel cmdline matters byte-for-byte (SEV-SNP measures the cmdline bytes). We append it after `rootfs_hash`, matching the read order in `init-sev`. If the launcher emits the hashes in a different position, SEV-with-docker-files quotes will produce `authentic_mismatch`. Please file an issue with a sample quote if you hit this.

## [0.7.0] — 2026-04-22

### Added

- **Docker-files verification** for TDX workloads. A SecretVM booted with a Dockerfiles archive baked into its image extends RTMR3 with a third entry — the SHA-256 of that archive — on top of the usual `[SHA256(compose), rootfs_data]` replay. This release adds offline support for that third entry.
  - SDK: `verifyTdxWorkload` / `verify_tdx_workload` and the auto-detect `verifyWorkload` / `verify_workload` now accept an optional docker-files input — either raw bytes (hashed client-side) or a precomputed SHA-256 hex digest.
  - CLI: `--verify-workload` gains `--docker-files <tar>` and `--docker-files-sha256 <hex>`. Only one is needed; the former reads the archive and computes the digest locally, the latter skips the read.
  - Mirrors the TDX initramfs behaviour in `scrtlabs/secret-vm-build` (`init-tdx` appends `SHA256(/mnt/docker-files.tar)` to RTMR3 when the archive is present). Fully offline — no network calls.
  - SEV-SNP is unchanged: docker-files measurement on SEV flows through kernel cmdline, not RTMR, and is already covered by the existing SEV path.

## [0.6.1] — 2026-04-20

### Added

- **`--json` CLI flag** — emits a minimal JSON form of the result: `valid`, `attestationType` (`attestation_type` in Python), `checks`, `errors`. The verbose `report` field (parsed CPU/GPU/proof-of-cloud contents) is omitted. Use `--raw` if you need the full result with `report`. Works across every CLI verb (`--secretvm`, `--cpu`, `--tdx`, `--sev`, `--gpu`, `-rv`, `-vw`, `--check-agent`, `--agent`).

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
