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

**Provenance:** confirmed by directly fetching `proofofcloud/trust-server`
`src/server.js` and `src/services.js` from `main` on 2026-06-24. The `main`
branch registers `app.post("/check_quote", ...)` → `checkQuote(quote)` in
`services.js`, which returns the `{whitelisted, machine_id, revoked?,
revoked_at?}` shapes below and treats a whitelist miss as a 200 (not an error).
A web-search snapshot of the repo may show an older revision without this route
— the live `main` source is authoritative here. (Note: not every *deployed*
peer runs current `main`. As of 2026-06-24, `trust-server.nillion.network`
returns **HTTP 404 with an HTML body** for `POST /check_quote` — it runs an
older build that only exposes `/get_jwt`. The failover logic below must treat
such a peer as "not a usable answer" and continue, which is exactly why
non-200 and non-JSON responses are failure cases.)

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

The ProofOfCloud module will expose a small helper, `toHexQuote(cpuData)`, that
returns the canonical **lowercase** hex string (the TDX path is also lowercased,
so the helper's output is uniformly lowercase even though the server regex would
accept uppercase), and errors clearly if the input matches neither hex nor
base64.

**Strict validation (do not rely on the detector alone).** The existing
detectors only sniff the leading header bytes, and `Buffer.from(text, "hex")` /
`bytes.fromhex` can silently truncate or partially accept malformed input. The
helper must therefore validate the *whole* string before sending:

- TDX path: after `trim()`, require the entire string to match
  `^[0-9a-fA-F]+$` with even length; lowercase it. Reject otherwise.
- SEV-SNP path: strict base64 decode of the whole string (no silent
  truncation), then re-encode the decoded bytes as lowercase hex.
- If neither validates, return an encode error (no network call is made).

## Trust model: failover (first usable answer)

Peers are tried **in list order**. For each peer:

1. `POST {peer}/check_quote` with `{"quote": "<hex>"}` and a per-peer timeout
   of **10 seconds**.
2. A **usable answer** is: HTTP 200, body parses as JSON, `whitelisted` is a
   JSON **boolean**, and `machine_id` is a **non-empty string**. If `revoked` is
   present it must be a boolean; when `revoked === true`, `revoked_at` is read as
   a string (a missing/non-string `revoked_at` is tolerated and reported as
   `null`). The first such answer is accepted and iteration stops.
3. Anything else (network/timeout error, non-200 status, body not JSON, or JSON
   with `whitelisted`/`machine_id` missing or of the wrong type) is recorded as
   that peer's failure reason and iteration continues to the next peer. A peer
   that doesn't implement the route (e.g. a 404 with an HTML body, as
   `trust-server.nillion.network` currently returns) lands here via the non-200
   / not-JSON checks.

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

**Assumption — peers share a whitelist source.** Because failover stops at the
first *usable* answer (including a definitive `whitelisted: false`), peer order
can in principle change the verdict if two peers disagree. This is acceptable
**only** under the assumption that all peers derive their whitelist and
revocation lists from the same Proof of Cloud database (the trust-server README
states both lists are "sourced from the Proof of Cloud database"). We rely on
that shared source: any peer's answer is treated as authoritative for the
machine. If that assumption ever breaks, this design would need to revisit
consensus. This assumption is documented, not enforced.

## Peer list management: bundle + auto-refresh

Mirror the repo's existing artifact-registry pattern
(`refreshRegistryFromGitHub` in `node/src/artifacts.ts`;
`refresh_registry_from_github` in `python/src/secretvm/verify/workload.py`).

- **Bundled copy:** `trust_server_peers.txt` ships in both data dirs:
  - `node/data/trust_server_peers.txt`
  - `python/src/secretvm/verify/data/trust_server_peers.txt`

  Seeded with the three current peers, one URL per line.

- **Refresh (once per process, best-effort, in-memory-first):** the first time a
  ProofOfCloud check runs in a process, attempt **one** fetch of the raw GitHub
  `peers_list.txt` with a **5-second timeout**. The resolved peer list is then
  memoized at module level and reused by subsequent checks in the same process —
  it is **not** re-fetched on every call. (This is a deliberate divergence from
  the cited registry-refresh pattern, which fetches only on a registry *miss*:
  refreshing + writing to the package dir on every verification would add a
  GitHub round-trip and a file write to every check and would fail on read-only
  installs.)

  - If the fetch+parse yields a **non-empty** list of valid peers: use that list
    (in memory) for this process, regardless of whether persisting it to disk
    succeeds.
  - **Best-effort persist:** also try to overwrite the bundled copy on disk so a
    future *offline* process starts from the newer list. If the write fails
    (read-only install — Docker, system site-packages, global npm), ignore the
    error; the in-memory list is still used this process.
  - On **any** fetch failure (network error, timeout, non-200, empty body, parse
    yields zero valid peers): fall back to the bundled copy on disk, silently.
    The check still proceeds. A hung/slow GitHub connection cannot stall the
    check beyond the 5-second refresh timeout.

- **Parsing (shared by both the refreshed text and the bundled file):**
  - Split on newlines; `trim()` each line; skip blank lines and lines starting
    with `#`.
  - Parse each remaining line with the platform URL parser. Keep a line **only**
    if it parses and its protocol is exactly `https:`. Reduce it to its
    **origin** (`scheme://host[:port]`), discarding any path, query, or
    fragment, so the request URL is always `{origin}/check_quote` with no double
    slashes or stray path segments. Invalid or non-`https:` lines are dropped
    individually (a malformed line does not discard the whole list).
  - A refreshed list is "valid" iff it yields **≥1** peer after this filtering;
    otherwise refresh is treated as a failure and the bundled copy is used.

## Result shape (call-shape compatible; report contents change)

"Backward compatible" here means the *call shape* and *check name* are
unchanged, so existing integrations keep working without edits. The **contents**
of `report.proof_of_cloud` do change (the old secretai-specific fields are gone).

- Attestation type stays `"PROOF-OF-CLOUD"`.
- The check key stays `proof_of_cloud_verified` (boolean).
- `vm.py` / `vm.ts` / `agent.py` / `agent.ts` integration and the
  `--proof-of-cloud` CLI flag are untouched in their call shape.
- `report.proof_of_cloud` is **always populated on every return path** (success,
  not-whitelisted, revoked, no-peer-answered, and encode-failure). This matters
  because the callers copy it only when present (`vm.ts`/`agent.ts` guard on
  `!== undefined`; `vm.py`/`agent.py` guard on `is not None`) — always
  populating it keeps the top-level report shape consistent. Contents:

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

  - `trust_server` is the peer URL whose answer was accepted, or `null` if no
    peer returned a usable answer / the quote could not be encoded.
  - `machine_id` is `null` when no peer answered or on encode failure.
  - `whitelisted` is `false` and `revoked` is `false` in every non-pass path.
  - `peers_tried` lists every peer attempted, in order (empty `[]` on encode
    failure, since no peer is contacted).

The old curated fields (`origin`, `status`, `proof_of_cloud`) are removed; they
were specific to the secretai quote-parse response and have no equivalent here.

The `vm.*`/`agent.*` integration currently copies
`poc_result.report["proof_of_cloud"]` into the top-level report when present —
that behavior is preserved unchanged (it copies whatever the new curated object
is).

## Components / boundaries

New/changed units, each independently testable:

1. **Peer list loader + refresher** (per SDK)
   - `loadBundledPeers()` → `string[]` — read the bundled file, parse per the
     rules above (https-only origins). Used as the offline fallback.
   - `resolvePeers()` → `string[]` — module-memoized: on first call, attempt
     `refreshPeersFromGitHub()`; use its result if it yielded ≥1 peer, else
     `loadBundledPeers()`. Cache and return the same list for the rest of the
     process.
   - `refreshPeersFromGitHub()` → `string[] | null` — fetch the raw GitHub list
     with a **5s timeout**, parse it; return the parsed peers if ≥1 valid,
     else `null`. Best-effort persist the raw text to the bundled file; ignore
     write errors. Never throws (any error → `null`).
   - Depends on: filesystem (data dir), network (GitHub raw, 5s timeout).

2. **Quote→hex encoder** (per SDK)
   - `toHexQuote(cpuData)` → lowercase hex string; reuses existing quote-type
     detection **and** strictly validates the whole string (full hex regex for
     TDX; strict base64 for SEV-SNP) before returning. Errors clearly on
     unrecognized/invalid input.
   - Depends on: existing `cpu` detection helpers.

3. **Single-peer query** (per SDK)
   - `queryPeer(peerUrl, hexQuote)` → either a parsed usable answer
     `{whitelisted, machine_id, revoked, revoked_at}` or a failure reason
     string.
   - Depends on: network, **10s timeout** (Node: `AbortSignal.timeout(10000)`,
     since `fetch` has no native timeout option; Python: `requests` `timeout=`).

4. **Orchestrator** = `checkProofOfCloud` / `check_proof_of_cloud`
   - `toHexQuote` (encode error → early return with populated report) →
     `resolvePeers()` → for each peer call `queryPeer` until first usable answer
     → build `AttestationResult` (report always populated).
   - Python keeps `check_proof_of_cloud_async` as the async variant
     (`asyncio.to_thread` over the sync path, so blocking network never blocks
     the event loop).

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

These rewrite the existing PoC test blocks (`node/src/index.test.ts` currently
asserts the old `secretai.scrtlabs.com/api/quote-parse` URL/body and uses
non-quote strings; `python/tests/test_verification.py` mocks
`secretvm.verify.check_proof_of_cloud` in the VM/agent integration tests — those
integration mocks stay, but the PoC-module tests are replaced).

**Mock dispatch by URL.** The new code issues two distinct HTTP shapes: the
GitHub `raw.githubusercontent.com/.../peers_list.txt` GET (returns newline text)
and the peer `POST {origin}/check_quote` (returns JSON). Tests must branch the
mock on the URL/host so the refresh GET and the peer POSTs don't cross-feed
(e.g. JSON returned to the peers-list parser). Node mocks `globalThis.fetch`;
Python mocks `requests` for peer queries and `urllib.request.urlopen` for the
refresh fetch. Reset the module-level peers memoization between tests.

Cases (both SDKs):

- TDX quote (hex) is sent to a peer unchanged; pass on `whitelisted:true`.
- SEV-SNP quote (base64) is converted to lowercase hex before sending; pass.
- First peer errors (network / non-200 / 404-HTML / malformed JSON) → second
  peer answers → verdict taken from second peer; `peers_tried` shows both.
- All peers fail → `proof_of_cloud_verified:false`, `report.proof_of_cloud`
  populated (`trust_server:null`, `machine_id:null`), per-peer reasons in errors.
- `whitelisted:false` → fail with not-whitelisted error.
- `revoked:true` → fail with revocation error and `revoked_at` in report.
- Refresh success → new list used (peer from refreshed list is queried);
  refresh failure / timeout → falls back to bundled list, check still runs.
- Refresh fetch+validate succeeds but disk write fails (simulate read-only) →
  in-memory refreshed list still used.
- Malformed peers line / non-`https:` line is dropped without discarding the
  rest of the list.
- Unrecognized or truncatable `cpu_data` (e.g. `0400000081000000zz`) → clear
  encode error, no network call, `peers_tried:[]`.

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
- Docs: `README.md`, `node/README.md`, `python/README.md`,
  `docs/sdk/verification-checks.md` (all reference the old quote-parse endpoint
  and/or old report fields and must be updated).
- Package data manifests so the new data file ships:
  - Python: `pyproject.toml` `[tool.setuptools.package-data]` currently lists
    only `data/*.csv` and `data/*.json` — add `data/*.txt`.
  - Node: `package.json` `files` already includes `data/`. Unlike `sev.json`/
    `tdx.csv` (copied from `artifacts_registry/` by the `prebuild` script),
    `trust_server_peers.txt` is committed directly into `node/data/` and is not
    produced by `prebuild`; keep both committed copies in sync manually.
