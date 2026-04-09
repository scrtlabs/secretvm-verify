/**
 * On-disk cache for AMD KDS responses (VCEK, cert chain, CRL).
 *
 * The cache lives at `~/.cache/secretvm-verify/amd/` by default. Each cached
 * entry is two files: the payload, and a sidecar `<key>.expires` containing
 * the Unix-epoch expiration time as a string. Reads check the sidecar and
 * return the payload only if it's still fresh; misses fall through to the
 * network. The {@link getStale} helper returns the payload regardless of
 * freshness, used as a fallback when the network is unreachable.
 *
 * The cache is on by default for the AMD SEV-SNP verifier in
 * `checkSevCpuAttestation` to minimize calls to `kdsintf.amd.com` and avoid
 * the rate-limit (HTTP 429) failures that the unauthenticated KDS endpoint
 * imposes when called repeatedly.
 */

import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

function cacheRoot(): string {
  const env = process.env.SECRETVM_VERIFY_CACHE_DIR;
  if (env) return join(env, "amd");
  return join(homedir(), ".cache", "secretvm-verify", "amd");
}

function keyPaths(category: string, key: string): { payload: string; expires: string } {
  const dir = join(cacheRoot(), category);
  let safe = key.replace(/[^A-Za-z0-9_\-]/g, "_");
  if (safe.length > 200) {
    safe = createHash("sha256").update(key).digest("hex");
  }
  return { payload: join(dir, safe), expires: join(dir, safe + ".expires") };
}

/** Return cached bytes if the entry exists and is still fresh, else null. */
export function get(category: string, key: string): Buffer | null {
  const { payload, expires } = keyPaths(category, key);
  if (!existsSync(payload) || !existsSync(expires)) return null;
  try {
    const expiresAt = parseFloat(readFileSync(expires, "utf8").trim());
    if (!Number.isFinite(expiresAt) || expiresAt < Date.now() / 1000) {
      return null;
    }
    return readFileSync(payload);
  } catch {
    return null;
  }
}

/**
 * Return cached bytes regardless of freshness, or null if missing.
 *
 * Used as a fallback when the network is unreachable: a stale CRL is better
 * than no CRL at all, since the alternative is failing every verification
 * while AMD KDS is down.
 */
export function getStale(category: string, key: string): Buffer | null {
  const { payload } = keyPaths(category, key);
  if (!existsSync(payload)) return null;
  try {
    return readFileSync(payload);
  } catch {
    return null;
  }
}

/** Atomically write a payload + expiration sidecar to disk. */
export function put(
  category: string,
  key: string,
  data: Uint8Array,
  ttlSeconds: number,
): void {
  const { payload, expires } = keyPaths(category, key);
  mkdirSync(dirname(payload), { recursive: true });
  const expiresAt = Date.now() / 1000 + ttlSeconds;
  const tmp = payload + ".tmp";
  writeFileSync(tmp, data);
  renameSync(tmp, payload);
  writeFileSync(expires, String(expiresAt));
}

// Default TTLs
export const TTL_VCEK_SECONDS = 30 * 86400; // 30 days — VCEK is stable per (chip, TCB) tuple
export const TTL_CHAIN_SECONDS = 30 * 86400; // 30 days — AMD CA chain very rarely rotates
export const TTL_CRL_SECONDS = 7 * 86400; //  7 days — matches AMD's typical nextUpdate window
