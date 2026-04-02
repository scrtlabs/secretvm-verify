import crypto from "node:crypto";
import { AttestationResult, makeResult } from "./types.js";
import { isVmUrl, fetchGpuQuote } from "./url.js";

const NRAS_URL = "https://nras.attestation.nvidia.com/v4/attest/gpu";
const NRAS_JWKS_URL =
  "https://nras.attestation.nvidia.com/.well-known/jwks.json";

// ---------------------------------------------------------------------------
// JWT helpers
// ---------------------------------------------------------------------------

function base64urlDecode(s: string): Buffer {
  return Buffer.from(s + "=".repeat((4 - (s.length % 4)) % 4), "base64url");
}

function decodeJwtHeader(token: string): Record<string, any> {
  return JSON.parse(base64urlDecode(token.split(".")[0]!).toString());
}

function decodeJwtPayload(token: string): Record<string, any> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error(`Invalid JWT: expected 3 parts`);
  return JSON.parse(base64urlDecode(parts[1]!).toString());
}

async function fetchJwks(): Promise<Map<string, any>> {
  const resp = await fetch(NRAS_JWKS_URL);
  if (!resp.ok) throw new Error(`JWKS fetch failed: ${resp.status}`);
  const jwks = (await resp.json()) as any;
  const keys = new Map<string, any>();
  for (const key of jwks.keys ?? []) {
    if (key.kid) keys.set(key.kid, key);
  }
  return keys;
}

function verifyJwtSignature(
  token: string,
  jwks: Map<string, any>,
): boolean {
  const header = decodeJwtHeader(token);
  const { kid, alg } = header;
  if (alg !== "ES384") return false;
  if (!jwks.has(kid)) return false;

  const jwk = jwks.get(kid)!;

  let pubKey: crypto.KeyObject;
  const x5c: string[] = jwk.x5c ?? [];
  if (x5c.length > 0) {
    const cert = new crypto.X509Certificate(
      Buffer.from(x5c[0]!, "base64"),
    );
    pubKey = cert.publicKey;
  } else {
    pubKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
  }

  const parts = token.split(".");
  const signedData = Buffer.from(`${parts[0]}.${parts[1]}`);
  const sigRaw = base64urlDecode(parts[2]!);

  // ES384: raw R||S (48+48), convert to DER
  const r = sigRaw.subarray(0, 48);
  const s = sigRaw.subarray(48);
  const derSig = ecdsaRsToDer(r, s);

  const verifier = crypto.createVerify("SHA384");
  verifier.update(signedData);
  try {
    return verifier.verify({ key: pubKey, dsaEncoding: "der" }, derSig);
  } catch {
    return false;
  }
}

function ecdsaRsToDer(r: Buffer, s: Buffer): Buffer {
  function encodeInt(v: Buffer): Buffer {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    let trimmed = v.subarray(i);
    if (trimmed[0]! & 0x80) {
      trimmed = Buffer.concat([Buffer.from([0x00]), trimmed]);
    }
    return Buffer.concat([Buffer.from([0x02, trimmed.length]), trimmed]);
  }
  const ri = encodeInt(r);
  const si = encodeInt(s);
  return Buffer.concat([Buffer.from([0x30, ri.length + si.length]), ri, si]);
}

// ---------------------------------------------------------------------------
// Public
// ---------------------------------------------------------------------------

export async function checkNvidiaGpuAttestation(
  dataOrUrl: string,
): Promise<AttestationResult> {
  const data = isVmUrl(dataOrUrl) ? await fetchGpuQuote(dataOrUrl) : dataOrUrl;
  const errors: string[] = [];
  const checks: Record<string, boolean> = {};

  // Parse input
  let attestationData: any;
  try {
    attestationData = JSON.parse(data);
    checks.input_parsed = true;
  } catch (e: any) {
    return makeResult("NVIDIA-GPU", {
      checks: { input_parsed: false },
      errors: [e.message],
    });
  }

  // Submit to NRAS
  let nrasResponse: any[];
  try {
    const resp = await fetch(NRAS_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(attestationData),
    });
    if (!resp.ok) {
      const text = await resp.text();
      errors.push(`NRAS returned ${resp.status}: ${text.slice(0, 200)}`);
      checks.nras_submission = false;
      return makeResult("NVIDIA-GPU", { checks, errors });
    }
    nrasResponse = (await resp.json()) as any[];
    checks.nras_submission = true;
  } catch (e: any) {
    errors.push(`NRAS request failed: ${e.message}`);
    checks.nras_submission = false;
    return makeResult("NVIDIA-GPU", { checks, errors });
  }

  // Fetch JWKS
  let jwks: Map<string, any>;
  try {
    jwks = await fetchJwks();
  } catch (e: any) {
    errors.push(`Failed to fetch NVIDIA JWKS: ${e.message}`);
    jwks = new Map();
  }

  const report: Record<string, any> = {};
  let allSigsValid = true;

  // Platform JWT
  const jwtEntry = nrasResponse[0];
  if (Array.isArray(jwtEntry) && jwtEntry[0] === "JWT") {
    const platformToken: string = jwtEntry[1];
    const sigValid =
      jwks.size > 0 ? verifyJwtSignature(platformToken, jwks) : false;
    checks.platform_jwt_signature = sigValid;
    if (!sigValid) {
      allSigsValid = false;
      errors.push("Platform JWT signature verification failed");
    }

    const claims = decodeJwtPayload(platformToken);
    report.overall_result = claims["x-nvidia-overall-att-result"];
    report.subject = claims.sub;
    report.issuer = claims.iss;
    report.nonce = claims.eat_nonce;
  }

  // Per-GPU JWTs
  const gpuEntries: Record<string, string> = nrasResponse[1] ?? {};
  const gpuReports: Record<string, any> = {};
  if (typeof gpuEntries === "object" && !Array.isArray(gpuEntries)) {
    for (const [gpuId, token] of Object.entries(gpuEntries)) {
      const sigValid =
        jwks.size > 0 ? verifyJwtSignature(token, jwks) : false;
      checks[`${gpuId}_jwt_signature`] = sigValid;
      if (!sigValid) {
        allSigsValid = false;
        errors.push(`${gpuId} JWT signature verification failed`);
      }

      const claims = decodeJwtPayload(token);
      gpuReports[gpuId] = {
        model: claims.hwmodel,
        oem_id: claims.oemid,
        ueid: claims.ueid,
        debug_status: claims.dbgstat,
        secure_boot: claims.secboot,
        driver_version: claims["x-nvidia-gpu-driver-version"],
        vbios_version: claims["x-nvidia-gpu-vbios-version"],
        attestation_report_parsed:
          claims["x-nvidia-gpu-attestation-report-parsed"],
        attestation_report_signature_verified:
          claims["x-nvidia-gpu-attestation-report-signature-verified"],
        attestation_report_nonce_match:
          claims["x-nvidia-gpu-attestation-report-nonce-match"],
        arch_check: claims["x-nvidia-gpu-arch-check"],
        measurements: claims.measres,
      };
    }
  }
  report.gpus = gpuReports;

  const valid = !!report.overall_result && allSigsValid;

  return makeResult("NVIDIA-GPU", { valid, checks, report, errors });
}
