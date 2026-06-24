# ProofOfCloud via trust-server peers — Design

Date: 2026-06-24
Status: Approved (pre-implementation)

## Background

Today the ProofOfCloud check in `secretvm-verify` delegates to a single SCRT
Labs endpoint:

- Node: `node/src/proofOfCloud.ts` — `checkProofOfCloud(quote)`
- Python: `python/src/secretvm/verify/proof_of_cloud.py` —
  `check_proof_of_cloud(quote)` and `check_proof_of_cloud_async(quote)`

Both POST the raw quote text to `https://secretai.scrtlabs.com/api/quote-parse`
as `{"quote": "<text>"}` and pass the check (`proof_of_cloud_verified`) iff the
response is HTTP 200 with `proof_of_cloud: true`. The verdict is only as
trustworthy as that single host.

The check is opt-in (`check_proof_of_cloud=True` / `--proof-of-cloud`) and is
wired into both VM verification (`vm.py` / `vm.ts`) and agent verification
(`agent.py` / `agent.ts`). When enabled, `proof_of_cloud_verified` is a required
check for overall validity.

## Goal

Replace the single-endpoint call with a failover query across the
community-vetted **trust-server peers**, calling each peer's
`POST /check_quote` endpoint. The list of peers is published at:

```
https://github.com/proofofcloud/trust-server/blob/main/public_info/peers_list.txt
(raw: https://raw.githubusercontent.com/proofofcloud/trust-server/main/public_info/peers_list.txt)
```

As of this writing it contains three peers:

```
https://trust-server.scrtlabs.com/
https://trust-server.nillion.network
https://trust-server.iex.ec/
```

## The trust-server `/check_quote` API

(Confirmed against `proofofcloud/trust-server` `src/server.js` and
`src/services.js`.)

- **Path:** `POST /check_quote` (underscore, **not** `/check-quote`).
- **Request body:** `{"quote": "<hex_encoded_quote>"}`. The server rejects any
  quote that is not a pure hex string (`^[0-9a-fA-F]+$`).
- **Response (HTTP 200):**
  - Whitelisted: `{"whitelisted": true, "machine_id": "<hex>"}`
  - Not whitelisted, not revoked: `{"whitelisted": false, "machine_id": "<hex>"}`
  - Revoked (precedence over whitelist):
    `{"whitelisted": false, "machine_id": "<hex>", "revoked": true, "revoked_at": "<iso8601>"}`
- **Errors:** the `/check_quote` path returns HTTP 500 with
  `{"error": "<message>"}` on a missing/malformed/invalid quote or verifier
  failure. (Whitelist misses are *not* errors — they return 200 with
  `whitelisted: false`.)

Architecture detection inside the server is by hex length: quotes whose hex is
longer than 8000 chars (~4000 bytes) are treated as Intel TDX/SGX (DCAP);
shorter quotes are treated as AMD SEV-SNP.

## Quote encoding

The trust-server requires a **hex** quote. The SDK's `cpu_data` (fetched from
the VM's `/cpu` endpoint) is:

- **Intel TDX:** already hex → send trimmed, as-is.
- **AMD SEV-SNP:** base64 → must be decoded and re-encoded as lowercase hex
  before sending.

Detection reuses the existing logic:

- Node: `node/src/cpu.ts` quote-type detection (hex ⇒ TDX, base64 ⇒ SEV-SNP).
- Python: `_detect_cpu_quote_type` in `python/src/secretvm/verify/cpu.py`.

The ProofOfCloud module will expose a small helper that takes `cpu_data` and
returns the canonical lowercase-hex string, raising/erroring clearly if the
input matches neither hex nor base64.

## Trust model: failover (first usable answer)

Peers are tried **in list order**. For each peer:

1. `POST {peer}/check_quote` with `{"quote": "<hex>"}` and a per-peer timeout
   of **10 seconds**.
2. A **usable answer** is: HTTP 200, body parses as JSON, and the body contains
   a boolean `whitelisted` field and a `machine_id`. The first usable answer is
   accepted and iteration stops.
3. Anything else (network/timeout error, non-200 status, body not JSON, or JSON
   missing the expected fields) is recorded as that peer's failure reason and
   iteration continues to the next peer.

Verdict from the accepted answer:

- **Pass** (`proof_of_cloud_verified = true`) iff `whitelisted === true` and the
  answer is not `revoked`.
- If `revoked === true`: **fail**, surface `revoked_at`, and add a
  revocation-specific error
  (`Machine <id> was revoked on <revoked_at>`).
- If `whitelisted === false` and not revoked: **fail** with
  `Machine <id> is not whitelisted by trust-server peer <url>`.

If **no peer** returns a usable answer: `proof_of_cloud_verified = false`, with
an error summarizing each peer's failure reason.

A single community-vetted peer is sufficient to produce a verdict; the remaining
peers exist as fallbacks for availability. (Quorum/consensus was explicitly
considered and rejected for this iteration.)

## Peer list management: bundle + auto-refresh

Mirror the repo's existing artifact-registry pattern
(`refreshRegistryFromGitHub` in `node/src/artifacts.ts`;
`refresh_registry_from_github` in `python/src/secretvm/verify/workload.py`).

- **Bundled copy:** `trust_server_peers.txt` ships in both data dirs:
  - `node/data/trust_server_peers.txt`
  - `python/src/secretvm/verify/data/trust_server_peers.txt`

  Seeded with the three current peers, one URL per line.

- **Refresh:** at the start of a ProofOfCloud check, attempt one fetch of the
  raw GitHub `peers_list.txt`. Validate it parses to a **non-empty** list of
  `https://` URLs; if so, overwrite the local bundled copy and use it. On **any**
  failure (network, non-200, empty, malformed, or no `https://` entries), keep
  the bundled copy silently — the check still proceeds against the bundled list.

- **Parsing:** one URL per line; `trim()` each line; skip blank lines and lines
  starting with `#`; strip a single trailing `/` from each URL so
  `{url}/check_quote` never produces a double slash. Only `https://` URLs are
  accepted (entries that don't start with `https://` are dropped, both on
  refresh-validation and when loading the bundled file).

- Refresh is attempted **once per check call** (not cached across calls within a
  process). This keeps behavior simple and predictable; the network cost is one
  small GET per verification, the same shape as the existing registry refresh.

## Result shape (backward compatible)

The public surface is unchanged so existing integrations keep working:

- Attestation type stays `"PROOF-OF-CLOUD"`.
- The check key stays `proof_of_cloud_verified` (boolean).
- `vm.py` / `vm.ts` / `agent.py` / `agent.ts` integration and the
  `--proof-of-cloud` CLI flag are untouched in their call shape.
- `report.proof_of_cloud` is still populated, but its **contents** change to
  reflect the trust-server response:

  ```json
  {
    "whitelisted": true,
    "machine_id": "<hex>",
    "revoked": false,
    "revoked_at": null,
    "trust_server": "https://trust-server.scrtlabs.com",
    "peers_tried": ["https://trust-server.scrtlabs.com"]
  }
  ```

  - `trust_server` is the peer URL whose answer was accepted (null if none
    answered).
  - `peers_tried` lists every peer attempted, in order (so a reader can see
    which peers were skipped/failed before one answered).

The old curated fields (`origin`, `status`, `proof_of_cloud`) are removed; they
were specific to the secretai quote-parse response and have no equivalent here.

The `vm.*`/`agent.*` integration currently copies
`poc_result.report["proof_of_cloud"]` into the top-level report when present —
that behavior is preserved unchanged (it copies whatever the new curated object
is).

## Components / boundaries

New/changed units, each independently testable:

1. **Peer list loader + refresher** (per SDK)
   - `loadBundledPeers()` → `string[]` (parsed, normalized, https-only).
   - `refreshPeersFromGitHub()` → `bool` (fetch+validate+overwrite; false on any
     error). Same contract as `refreshRegistryFromGitHub`.
   - Depends on: filesystem (data dir), network (GitHub raw).

2. **Quote→hex encoder** (per SDK)
   - `toHexQuote(cpuData)` → lowercase hex string; reuses existing quote-type
     detection. Errors clearly on unrecognized input.
   - Depends on: existing `cpu` detection helpers.

3. **Single-peer query** (per SDK)
   - `queryPeer(peerUrl, hexQuote)` → either a parsed usable answer
     `{whitelisted, machine_id, revoked?, revoked_at?}` or a failure reason
     string.
   - Depends on: network, 10s timeout.

4. **Orchestrator** = `checkProofOfCloud` / `check_proof_of_cloud`
   - Refresh peers (best-effort) → load peers → for each peer call `queryPeer`
     until first usable answer → build `AttestationResult`.
   - Python keeps `check_proof_of_cloud_async` as the async variant.

## Error handling summary

| Situation | `proof_of_cloud_verified` | errors[] |
|---|---|---|
| Peer answers `whitelisted:true`, not revoked | true | — |
| Peer answers `whitelisted:false`, not revoked | false | "Machine `<id>` is not whitelisted by trust-server peer `<url>`" |
| Peer answers `revoked:true` | false | "Machine `<id>` was revoked on `<revoked_at>`" |
| No peer returns a usable answer | false | one line per peer with its failure reason |
| `cpu_data` is neither hex nor base64 | false | "Could not encode quote for trust-server (unrecognized quote format)" |
| Peers list empty after load (should not happen — bundled is non-empty) | false | "No trust-server peers available" |

## Testing

Both SDKs (`node/src/index.test.ts`, `python/tests/test_verification.py`),
mocking HTTP:

- TDX quote (hex) is sent to a peer unchanged; pass on `whitelisted:true`.
- SEV-SNP quote (base64) is converted to hex before sending; pass.
- First peer errors (network/500/malformed) → second peer answers → verdict
  taken from second peer; `peers_tried` shows both.
- All peers fail → `proof_of_cloud_verified:false` with per-peer reasons.
- `whitelisted:false` → fail with not-whitelisted error.
- `revoked:true` → fail with revocation error and `revoked_at` in report.
- Refresh success overwrites bundled list and uses the new list; refresh
  failure falls back to bundled list (check still runs).
- Unrecognized `cpu_data` → clear encode error, no network call.

## Out of scope

- Quorum/consensus across peers (failover only this iteration).
- JWT issuance (`/get_jwt`) or token verification (`/verify_token`).
- Caching the peers list across process invocations.
- Shuffling/load-balancing peer order.

## Files touched

- `node/src/proofOfCloud.ts` (rewrite)
- `python/src/secretvm/verify/proof_of_cloud.py` (rewrite, keep async variant)
- `node/data/trust_server_peers.txt` (new)
- `python/src/secretvm/verify/data/trust_server_peers.txt` (new)
- Tests: `node/src/index.test.ts`, `python/tests/test_verification.py`
- Docs: `README.md`, `docs/sdk/verification-checks.md`
- Package data manifests so the new data file ships:
  - Python: `pyproject.toml` `[tool.setuptools.package-data]` currently lists
    only `data/*.csv` and `data/*.json` — add `data/*.txt`.
  - Node: `package.json` `files` already includes `data/`. Unlike `sev.json`/
    `tdx.csv` (copied from `artifacts_registry/` by the `prebuild` script),
    `trust_server_peers.txt` is committed directly into `node/data/` and is not
    produced by `prebuild`; keep both committed copies in sync manually.
