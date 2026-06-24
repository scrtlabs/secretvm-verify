import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { AttestationResult, makeResult, orderChecks } from "./types.js";
import { detectCpuQuoteType } from "./cpu.js";

const PEERS_GITHUB_RAW =
  "https://raw.githubusercontent.com/proofofcloud/trust-server/main/public_info/peers_list.txt";

function peersFilePath(): string {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  return join(__dirname, "..", "data", "trust_server_peers.txt");
}

// ---------------------------------------------------------------------------
// Quote -> canonical lowercase hex
// ---------------------------------------------------------------------------

/**
 * Encode a CPU quote (as served by the VM's /cpu endpoint) to a canonical
 * lowercase hex string suitable for the trust-server `/check_quote` API.
 *
 * Reuses the existing quote-type detector in cpu.ts (hex => TDX,
 * base64 => SEV-SNP) but then strictly validates the WHOLE string:
 *
 *   - TDX: the trimmed string must match /^[0-9a-fA-F]+$/ with even length.
 *     (We do NOT round-trip through Buffer.from(text, "hex"), which silently
 *     truncates at the first invalid character.)
 *   - SEV-SNP: strict base64 decode (no silent truncation), then re-encode the
 *     decoded bytes as lowercase hex.
 *
 * Throws on unrecognized / invalid input so the orchestrator can early-return
 * without making any network call.
 */
export function toHexQuote(cpuData: string): string {
  const text = cpuData.trim();
  const quoteType = detectCpuQuoteType(text);

  if (quoteType === "TDX") {
    if (text.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(text)) {
      throw new Error("invalid TDX hex quote");
    }
    return text.toLowerCase();
  }

  if (quoteType === "SEV-SNP") {
    const buf = Buffer.from(text, "base64");
    // Strict base64 check: re-encoding the decoded bytes must reproduce the
    // input (modulo padding/whitespace), otherwise base64 silently dropped
    // invalid characters.
    const normalized = text.replace(/\s+/g, "");
    const reencoded = buf.toString("base64");
    const stripPad = (s: string) => s.replace(/=+$/, "");
    if (buf.length === 0 || stripPad(reencoded) !== stripPad(normalized)) {
      throw new Error("invalid SEV-SNP base64 quote");
    }
    return buf.toString("hex").toLowerCase();
  }

  throw new Error("unrecognized quote format");
}

// ---------------------------------------------------------------------------
// Peer list loading + refresh
// ---------------------------------------------------------------------------

/** Parse newline-delimited peer text into a list of https origins. */
function parsePeers(content: string): string[] {
  const peers: string[] = [];
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    try {
      const u = new URL(line);
      if (u.protocol !== "https:") continue;
      peers.push(u.origin);
    } catch {
      // drop invalid line individually
    }
  }
  return peers;
}

/** Read and parse the bundled peers file (offline fallback). */
export function loadBundledPeers(): string[] {
  try {
    return parsePeers(readFileSync(peersFilePath(), "utf8"));
  } catch {
    return [];
  }
}

/**
 * Fetch the raw peers list from GitHub with a 5s timeout. Returns the parsed
 * peers if >=1 valid, else null. Best-effort persists the fetched raw text to
 * the bundled file (write errors are ignored). Never throws.
 */
export async function refreshPeersFromGitHub(): Promise<string[] | null> {
  try {
    const resp = await fetch(PEERS_GITHUB_RAW, {
      signal: AbortSignal.timeout(5000),
    });
    if (!resp.ok) return null;
    const text = await resp.text();
    const peers = parsePeers(text);
    if (peers.length < 1) return null;
    // best-effort persist for future offline starts
    try {
      writeFileSync(peersFilePath(), text, "utf8");
    } catch {
      // read-only install (Docker, global npm) — ignore
    }
    return peers;
  } catch {
    return null;
  }
}

let _peersCache: string[] | null = null;

/**
 * Resolve the peer list for this process. On first call, attempt one GitHub
 * refresh; use it if it yields >=1 peer, else fall back to the bundled file.
 * Memoized at module scope for the rest of the process.
 */
export async function resolvePeers(): Promise<string[]> {
  if (_peersCache) return _peersCache;
  const refreshed = await refreshPeersFromGitHub();
  _peersCache = refreshed ?? loadBundledPeers();
  return _peersCache;
}

/** Reset the module-level peers memoization (for tests). */
export function resetPeersCacheForTests(): void {
  _peersCache = null;
}

// ---------------------------------------------------------------------------
// Single-peer query
// ---------------------------------------------------------------------------

interface PeerAnswer {
  whitelisted: boolean;
  machine_id: string;
  revoked: boolean;
  revoked_at: string | null;
}

/**
 * Query one trust-server peer. Returns a parsed usable answer or a failure
 * reason string. A usable answer is HTTP 200 + JSON where `whitelisted` is a
 * boolean and `machine_id` is a non-empty string.
 */
async function queryPeer(
  peerUrl: string,
  hexQuote: string,
): Promise<PeerAnswer | string> {
  let resp: Response;
  try {
    resp = await fetch(`${peerUrl}/check_quote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ quote: hexQuote }),
      signal: AbortSignal.timeout(10000),
    });
  } catch (e: any) {
    return `${peerUrl}: request failed (${e?.message ?? e})`;
  }

  if (!resp.ok) {
    return `${peerUrl}: HTTP ${resp.status}`;
  }

  let body: any;
  try {
    body = await resp.json();
  } catch {
    return `${peerUrl}: response was not valid JSON`;
  }

  if (
    typeof body?.whitelisted !== "boolean" ||
    typeof body?.machine_id !== "string" ||
    body.machine_id.length === 0
  ) {
    return `${peerUrl}: unexpected response shape`;
  }

  let revoked = false;
  if (body.revoked !== undefined) {
    if (typeof body.revoked !== "boolean") {
      return `${peerUrl}: unexpected response shape (revoked)`;
    }
    revoked = body.revoked;
  }

  const revoked_at =
    revoked && typeof body.revoked_at === "string" ? body.revoked_at : null;

  return {
    whitelisted: body.whitelisted,
    machine_id: body.machine_id,
    revoked,
    revoked_at,
  };
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

function buildReport(over: Partial<Record<string, any>>): Record<string, any> {
  return {
    proof_of_cloud: {
      whitelisted: false,
      machine_id: null,
      revoked: false,
      revoked_at: null,
      trust_server: null,
      peers_tried: [],
      ...over,
    },
  };
}

/**
 * Verify a CPU quote against the community-vetted trust-server peers.
 *
 * The quote is encoded to canonical lowercase hex and POSTed to each peer's
 * `/check_quote` endpoint in list order until one returns a usable answer
 * (failover; first usable answer wins). The verdict passes iff the accepted
 * answer is `whitelisted` and not `revoked`.
 *
 * `report.proof_of_cloud` is always populated on every return path.
 */
export async function checkProofOfCloud(
  cpuData: string,
): Promise<AttestationResult> {
  const checks: Record<string, boolean> = {};
  const errors: string[] = [];

  // 1. Encode the quote to hex (no network call on failure).
  let hexQuote: string;
  try {
    hexQuote = toHexQuote(cpuData);
  } catch {
    errors.push(
      "Could not encode quote for trust-server (unrecognized quote format)",
    );
    checks.proof_of_cloud_verified = false;
    return makeResult("PROOF-OF-CLOUD", {
      checks: orderChecks(checks),
      report: buildReport({ peers_tried: [] }),
      errors,
    });
  }

  // 2. Resolve peers.
  const peers = await resolvePeers();
  if (peers.length === 0) {
    errors.push("No trust-server peers available");
    checks.proof_of_cloud_verified = false;
    return makeResult("PROOF-OF-CLOUD", {
      checks: orderChecks(checks),
      report: buildReport({ peers_tried: [] }),
      errors,
    });
  }

  // 3. Failover: try peers in order until first usable answer.
  const peersTried: string[] = [];
  const reasons: string[] = [];
  let answer: PeerAnswer | null = null;
  let trustServer: string | null = null;

  for (const peer of peers) {
    peersTried.push(peer);
    const res = await queryPeer(peer, hexQuote);
    if (typeof res === "string") {
      reasons.push(res);
      continue;
    }
    answer = res;
    trustServer = peer;
    break;
  }

  // 4. No usable answer from any peer.
  if (!answer || !trustServer) {
    for (const r of reasons) errors.push(r);
    checks.proof_of_cloud_verified = false;
    return makeResult("PROOF-OF-CLOUD", {
      checks: orderChecks(checks),
      report: buildReport({ peers_tried: peersTried }),
      errors,
    });
  }

  // 5. Build verdict from the accepted answer.
  if (answer.revoked) {
    errors.push(
      `Machine ${answer.machine_id} was revoked on ${answer.revoked_at}`,
    );
    checks.proof_of_cloud_verified = false;
    return makeResult("PROOF-OF-CLOUD", {
      checks: orderChecks(checks),
      report: buildReport({
        whitelisted: false,
        machine_id: answer.machine_id,
        revoked: true,
        revoked_at: answer.revoked_at,
        trust_server: trustServer,
        peers_tried: peersTried,
      }),
      errors,
    });
  }

  if (!answer.whitelisted) {
    errors.push(
      `Machine ${answer.machine_id} is not whitelisted by trust-server peer ${trustServer}`,
    );
    checks.proof_of_cloud_verified = false;
    return makeResult("PROOF-OF-CLOUD", {
      checks: orderChecks(checks),
      report: buildReport({
        whitelisted: false,
        machine_id: answer.machine_id,
        revoked: false,
        revoked_at: null,
        trust_server: trustServer,
        peers_tried: peersTried,
      }),
      errors,
    });
  }

  // Pass.
  checks.proof_of_cloud_verified = true;
  return makeResult("PROOF-OF-CLOUD", {
    valid: true,
    checks: orderChecks(checks),
    report: buildReport({
      whitelisted: true,
      machine_id: answer.machine_id,
      revoked: false,
      revoked_at: null,
      trust_server: trustServer,
      peers_tried: peersTried,
    }),
    errors,
  });
}
