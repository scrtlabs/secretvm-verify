# Changelog

All notable changes to `secretvm-verify` (both the Node and Python packages) are documented here.

## [Unreleased]

### Fixed

- **`report.dstack_app_id` is no longer reported as if it were attested.** The app-id is read from the VM's own `/info`, and it only becomes trustworthy when it is an input to a TDX RTMR3 replay that reproduces the quote. SEV-SNP has no app-id in its launch measurement (dstack KMS on AMD governs key release, not the measurement), so a `valid: true` SEV result proved nothing about it; the same held for any failed or mismatched TDX replay. Both SDKs now emit `report.dstack_app_id_verified` alongside the value — `true` only when the CPU quote verified, the quote is TDX, and the workload check returned `authentic_match`; `false` otherwise — and the field is set after the workload check rather than before it. The CPU-validity condition matters because verification does not stop at a failed CPU quote and the workload replay compares measurements without checking the DCAP signature, so `authentic_match` alone does not imply a hardware-signed quote.

## [0.13.0] — 2026-07-21

### Added

- **dstack RTMR3 measurement scheme.** Newer SecretVM images (dstack/gramine KMS) extend RTMR3 via `dstack-util` instead of `attest-tool`, which changes how each event is measured. The verifier now supports both schemes and picks between them by whether the VM reports a `dstack_app_id`:
  - **attest-tool (original images):** each event extends RTMR3 with the **raw hash** bytes — `sha256(compose)`, `rootfs_data`, `sha256(docker-files)?`.
  - **dstack-util (new images):** each event extends RTMR3 with a **dstack event digest** `sha384(LE32(0x08000001) ‖ ":" ‖ event_name ‖ ":" ‖ payload)`, for events `app-id`, `compose-hash`, `os-image-hash`, `docker-files-hash?` (payloads = the raw hash bytes; `app-id` payload = the dstack app-id).

  The `dstack_app_id` is fetched from the VM's `GET /info` endpoint (`{"dstack_app_id":"…"}`) and recorded as `report.dstack_app_id`. When `/info` is absent or reports an empty app-id (older images), the attest-tool scheme is used — so a mixed fleet stays verifiable. A new `--dstack-app-id <hex>` flag (Node CLI) supplies the id for offline (file-based) `--verify-workload`. Verified end-to-end against live `small/v0.0.34` prod and dev VMs. Mirrored in Node and Python.
- **Registry: `small` `v0.0.34` (TDX, prod + dev).** Added entries for the `small` template at `v0.0.34`.

## [0.12.0] — 2026-07-15

### Added

- **Split attestation vs inference endpoints.** New `resolveSecretVmEndpoints` / `--tls-url` (alias `--service-url`) let you verify `report_data` against a separate service TLS endpoint while quotes and workload still come from the primary VM URL. The result now records `report.attestation_url` and `report.tls_binding_url`.
- **Automatic port fallback for bare hosts.** A host with no explicit port now probes `GET /cpu` on `29343` first, then `21434`, and binds both the quote and TLS endpoints to whichever answers — supporting the host-net Caddy topology (e.g. jedi/rytn) where attest-rest is loopback-only and the public origin is `:21434`. An explicit port or `--tls-url` disables probing and preserves prior behavior. Mirrored in Node and Python.
- **SecretVM artifacts registry refresh.** Adds TDX `v0.0.33` GPU entries (`4xlarge_256GB_gpu` dev + prod, verified live against a running v0.0.33 GPU VM) and SEV-SNP `gpu_prod`/`gpu_dev` entries for `v0.0.33`. Synced across all three registry copies.

### Changed

- **TLS binding accepts SPKI or full-certificate digests.** The binding now matches on either `SHA-256(SubjectPublicKeyInfo DER)` (current) or `SHA-256(full certificate DER)` (legacy), recording `report.tls_binding_kind`. Keeps a mixed fleet (SPKI-pinned + older full-cert VMs) verifiable during rollout.
- **Stricter service-base URL parsing** (`node url.ts` / `python vm.py`): https-only; rejects userinfo, query, fragment, out-of-range ports, and percent-encoding; validates IPv6; and rejects concrete `/cpu`, `/gpu`, `/docker-compose` paths as a service-base URL.
- **Workload verification tolerates both docker-compose serving formats.** Older attest-rest wraps `/docker-compose` in an HTML `<pre>` block (with a trailing zero-width space); newer attest-rest serves the raw file bytes. Verification now tries both the raw response and the HTML-extracted content and accepts a match on either — the measurement (RTMR3 on TDX, `docker_compose_hash` on SEV) is bound in the quote, so the extra candidate can only confirm a legitimately measured compose, never admit a wrong one.

## [0.11.0] — 2026-07-06

### Added

- **GPU enforcement (`--enforce-gpu` / `enforce_gpu=True`)** — opt-in flag that requires a verifiable NVIDIA GPU attestation. A SecretVM whose `/gpu` endpoint returns no attestation now fails verification (a `gpu_present` check is recorded and folded into the required set) instead of passing as a CPU-only VM. Default is off, so existing behaviour is unchanged. Available on `checkSecretVm` / `check_secret_vm` (Node and Python, sync and async) and as a CLI flag; applies to `--secretvm`, `--k8scluster`, and the bare-URL form.

## [0.10.0] — 2026-06-30

### Changed

- **Proof of Cloud now verifies against the community trust-server peer network.** `checkProofOfCloud` / `check_proof_of_cloud` (and the `--proof-of-cloud` flag) now POST the CPU quote to the `/check_quote` endpoint of the community-vetted trust-server peers (`github.com/proofofcloud/trust-server`), failing over across peers in list order until the first usable answer, instead of calling a single SCRT Labs endpoint. The peer list ships bundled and is best-effort refreshed from GitHub once per process. The result reports `{whitelisted, machine_id, revoked, revoked_at, trust_server, peers_tried}`.

## [0.9.2] — 2026-05-27

### Added

- **Auto-refresh of artifact registry on miss.** When `verifyTdxWorkload` / `verifySevWorkload` (Node) or `verify_tdx_workload` / `verify_sev_workload` (Python) can't find a matching registry entry, the package now fetches the latest `tdx.csv` + `sev.json` from `github.com/scrtlabs/secretvm-verify/main/artifacts_registry`, writes them into the installed package's `data/` dir, and retries the lookup. Lets the CLI verify VMs running builds that shipped after the user's installed package version. A "Registry miss — fetching latest artifacts from GitHub..." note is printed to stderr when the refresh fires. Exposed as `refreshRegistryFromGitHub()` / `refresh_registry_from_github()` for programmatic callers.

### Changed

- **SecretVM artifacts registry refresh.** TDX: adds rows for `v0.0.28` (small/medium/large × dev/prod) and `gcp-v0.0.27` (large × dev-gcp/prod-gcp). SEV: adds `v0.0.28` and `gcp-v0.0.27` entries. Consumers on 0.9.1 will fall back to the auto-refresh path against these newer VMs; bumping picks them up at install time.

## [0.9.1] — 2026-05-12

### Changed

- **SecretVM artifacts registry refresh.** TDX: adds `small/medium/large × dev/prod` rows for `v0.0.27` and `large × dev-gcp/prod-gcp` rows for `v0.0.26-beta.1`. SEV: adds `v0.0.27` dev + prod entries. No code changes; consumers on 0.9.0 will fail `workload_binding_verified` against VMs running these newer builds.

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
