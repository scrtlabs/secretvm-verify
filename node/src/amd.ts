import crypto from "node:crypto";
import { fromBER, Integer, Sequence, UTCTime } from "asn1js";
import { utils as qvlUtils } from "@phala/dcap-qvl";
import { isVmUrl, fetchCpuQuote } from "./url.js";
import { AttestationResult, makeResult } from "./types.js";
import * as kdsCache from "./kdsCache.js";

/** Canonical hex form of an X.509 serial: uppercase, no leading zeros. */
function normalizeSerialHex(input: string): string {
  const hex = input.replace(/[^a-fA-F0-9]/g, "").toUpperCase();
  return hex.replace(/^0+(?=[0-9A-F])/g, "");
}

const AMD_KDS_BASE = "https://kdsintf.amd.com";

/**
 * Parse the `nextUpdate` field from a DER-encoded X.509 CRL.
 *
 * Returns the nextUpdate as a Date, or null if the CRL has no nextUpdate
 * field or parsing fails. We use this to size the AMD CRL cache TTL to the
 * CRL's own expiration window rather than a fixed value.
 *
 * X.509 CRL structure:
 *   CertificateList ::= SEQUENCE {
 *     tbsCertList SEQUENCE {
 *       version Version OPTIONAL,        -- INTEGER
 *       signature AlgorithmIdentifier,    -- SEQUENCE
 *       issuer Name,                      -- SEQUENCE
 *       thisUpdate Time,                  -- UTCTime or GeneralizedTime
 *       nextUpdate Time OPTIONAL,         -- the field we want
 *       ...
 *     },
 *     ...
 *   }
 *
 * GeneralizedTime extends UTCTime in asn1js, so a single `instanceof UTCTime`
 * check catches both encodings; both expose `toDate()`.
 */
function parseCrlNextUpdate(der: Uint8Array): Date | null {
  try {
    const parsed = fromBER(der);
    if (parsed.offset === -1) return null;

    const certList = parsed.result;
    if (!(certList instanceof Sequence)) return null;
    const tbsCertList = certList.valueBlock.value[0];
    if (!(tbsCertList instanceof Sequence)) return null;
    const children = tbsCertList.valueBlock.value;

    let i = 0;
    if (children[i] instanceof Integer) i++; // optional version
    i += 3; // signature AlgorithmIdentifier, issuer Name, thisUpdate Time
    if (i >= children.length) return null;

    const nextUpdate = children[i];
    if (nextUpdate instanceof UTCTime) return nextUpdate.toDate();
    return null;
  } catch {
    return null;
  }
}
const REPORT_SIZE = 0x4a0;
const SIG_OFFSET = 0x2a0;
const SIG_COMPONENT_SIZE = 72;
const SIG_VALUE_SIZE = 48;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface TcbVersion {
  bootLoader: number;
  tee: number;
  snp: number;
  microcode: number;
}

function parseTcb(buf: Buffer): TcbVersion {
  return {
    bootLoader: buf[0]!,
    tee: buf[1]!,
    snp: buf[6]!,
    microcode: buf[7]!,
  };
}

/** Convert raw little-endian R, S buffers to DER-encoded ECDSA signature. */
function ecdsaLeRsToDer(rLE: Buffer, sLE: Buffer): Buffer {
  // Reverse to big-endian
  const r = Buffer.from(rLE);
  r.reverse();
  const s = Buffer.from(sLE);
  s.reverse();

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
// Report parser
// ---------------------------------------------------------------------------

function parseReport(raw: Buffer) {
  if (raw.length < REPORT_SIZE) {
    throw new Error(
      `Report too short: ${raw.length} bytes (expected ${REPORT_SIZE})`,
    );
  }

  const version = raw.readUInt32LE(0x000);
  if (version < 2) {
    throw new Error(`Unsupported report version: ${version} (expected >= 2)`);
  }
  const sigAlgo = raw.readUInt32LE(0x034);
  if (sigAlgo !== 1) {
    throw new Error(
      `Unsupported signature algorithm: ${sigAlgo} (expected 1 = ECDSA-P384-SHA384)`,
    );
  }

  const policy = raw.readBigUInt64LE(0x008);
  const platformInfo = raw.readBigUInt64LE(0x040);

  return {
    version,
    guestSvn: raw.readUInt32LE(0x004),
    policy,
    familyId: raw.subarray(0x010, 0x020),
    imageId: raw.subarray(0x020, 0x030),
    vmpl: raw.readUInt32LE(0x030),
    signatureAlgo: sigAlgo,
    currentTcb: parseTcb(raw.subarray(0x038, 0x040)),
    platformInfo,
    authorKeyEn: raw.readUInt32LE(0x048),
    reportData: raw.subarray(0x050, 0x090),
    measurement: raw.subarray(0x090, 0x0c0),
    hostData: raw.subarray(0x0c0, 0x0e0),
    idKeyDigest: raw.subarray(0x0e0, 0x110),
    authorKeyDigest: raw.subarray(0x110, 0x140),
    reportId: raw.subarray(0x140, 0x160),
    reportIdMa: raw.subarray(0x160, 0x180),
    reportedTcb: parseTcb(raw.subarray(0x180, 0x188)),
    chipId: raw.subarray(0x1a0, 0x1e0),
    committedTcb: parseTcb(raw.subarray(0x1e0, 0x1e8)),
    currentBuild: raw[0x1e8]!,
    currentMinor: raw[0x1e9]!,
    currentMajor: raw[0x1ea]!,
    committedBuild: raw[0x1ec]!,
    committedMinor: raw[0x1ed]!,
    committedMajor: raw[0x1ee]!,
    launchTcb: parseTcb(raw.subarray(0x1f0, 0x1f8)),
    signatureR: raw.subarray(SIG_OFFSET, SIG_OFFSET + SIG_VALUE_SIZE),
    signatureS: raw.subarray(
      SIG_OFFSET + SIG_COMPONENT_SIZE,
      SIG_OFFSET + SIG_COMPONENT_SIZE + SIG_VALUE_SIZE,
    ),
    rawReport: raw.subarray(0, REPORT_SIZE),
    smtAllowed: !!(Number(policy) & (1 << 16)),
    debugAllowed: !!(Number(policy) & (1 << 19)),
  };
}

// ---------------------------------------------------------------------------
// AMD KDS
// ---------------------------------------------------------------------------

function vcekUrl(product: string, chipId: Buffer, tcb: TcbVersion): string {
  return (
    `${AMD_KDS_BASE}/vcek/v1/${product}/${chipId.toString("hex")}` +
    `?blSPL=${tcb.bootLoader}&teeSPL=${tcb.tee}` +
    `&snpSPL=${tcb.snp}&ucodeSPL=${tcb.microcode}`
  );
}

/** Stable cache key for the VCEK fetch — includes the full TCB tuple
 * because AMD issues a distinct VCEK per (chip, ucode, snp, tee, bl) level. */
function vcekCacheKey(
  product: string,
  chipId: Buffer,
  tcb: TcbVersion,
): string {
  return (
    `${product}_${chipId.toString("hex")}` +
    `_bl${tcb.bootLoader}_tee${tcb.tee}` +
    `_snp${tcb.snp}_uc${tcb.microcode}`
  );
}

/**
 * Stale cache fallback. In strict mode this returns null so the caller
 * fails closed; otherwise returns the stale entry if one exists.
 */
function staleFallback(
  kind: string,
  key: string,
  strict: boolean,
): Buffer | null {
  if (strict) return null;
  return kdsCache.getStale(kind, key);
}

async function fetchVcek(
  product: string,
  chipId: Buffer,
  reportedTcb: TcbVersion,
  reloadAmdKds = false,
  strict = false,
): Promise<{ der: Buffer; product: string }> {
  const candidates = product ? [product] : ["Genoa", "Milan", "Turin"];
  for (const name of candidates) {
    const cacheKey = vcekCacheKey(name, chipId, reportedTcb);
    if (!reloadAmdKds) {
      const cached = kdsCache.get("vcek", cacheKey);
      if (cached) {
        return { der: cached, product: name };
      }
    }
    const url = vcekUrl(name, chipId, reportedTcb);
    let resp: Response;
    try {
      resp = await fetch(url);
    } catch (e) {
      // Network failure: fall back to a stale cached entry if we have one
      // (unless strict mode, in which case fail closed).
      const stale = staleFallback("vcek", cacheKey, strict);
      if (stale) return { der: stale, product: name };
      throw e;
    }
    if (resp.ok) {
      const der = Buffer.from(await resp.arrayBuffer());
      kdsCache.put("vcek", cacheKey, der, kdsCache.TTL_VCEK_SECONDS);
      return { der, product: name };
    }
    if (resp.status === 429) {
      // Last-ditch fallback: serve a stale cached entry rather than fail.
      const stale = staleFallback("vcek", cacheKey, strict);
      if (stale) return { der: stale, product: name };
      throw new Error(
        "AMD KDS rate-limited (429). Retry later or specify product.",
      );
    }
    if (product) {
      const stale = staleFallback("vcek", cacheKey, strict);
      if (stale) return { der: stale, product: name };
      throw new Error(`AMD KDS returned ${resp.status}`);
    }
  }
  throw new Error(
    "Could not fetch VCEK for any known product (Genoa/Milan/Turin)",
  );
}

async function fetchChainPem(
  product: string,
  reloadAmdKds = false,
  strict = false,
): Promise<string> {
  if (!reloadAmdKds) {
    const cached = kdsCache.get("cert_chain", product);
    if (cached) return cached.toString("utf8");
  }
  const url = `${AMD_KDS_BASE}/vcek/v1/${product}/cert_chain`;
  let resp: Response;
  try {
    resp = await fetch(url);
  } catch (e) {
    const stale = staleFallback("cert_chain", product, strict);
    if (stale) return stale.toString("utf8");
    throw e;
  }
  if (!resp.ok) {
    const stale = staleFallback("cert_chain", product, strict);
    if (stale) return stale.toString("utf8");
    throw new Error(`AMD KDS cert_chain returned ${resp.status}`);
  }
  const text = await resp.text();
  kdsCache.put("cert_chain", product, Buffer.from(text, "utf8"), kdsCache.TTL_CHAIN_SECONDS);
  return text;
}

/** Fetch the AMD VCEK CRL for a product, cache-first.
 *
 * The CRL is consulted to detect chips that AMD has revoked. The cache TTL
 * is computed from the CRL's own X.509 `nextUpdate` field, so the cache
 * naturally aligns with AMD's published refresh schedule. If the CRL has no
 * `nextUpdate` (rare) or parsing fails, we fall back to a 7-day TTL.
 * On network failure we fall back to a stale cached entry rather than
 * failing every SEV verification while KDS is down (unless strict=true,
 * in which case the caller wants to fail closed instead).
 */
async function fetchCrl(
  product: string,
  reloadAmdKds = false,
  strict = false,
): Promise<Buffer> {
  if (!reloadAmdKds) {
    const cached = kdsCache.get("crl", product);
    if (cached) return cached;
  }
  const url = `${AMD_KDS_BASE}/vcek/v1/${product}/crl`;
  let resp: Response;
  try {
    resp = await fetch(url);
  } catch (e) {
    const stale = staleFallback("crl", product, strict);
    if (stale) return stale;
    throw e;
  }
  if (!resp.ok) {
    const stale = staleFallback("crl", product, strict);
    if (stale) return stale;
    throw new Error(`AMD KDS crl returned ${resp.status}`);
  }
  const der = Buffer.from(await resp.arrayBuffer());

  // Use the CRL's own nextUpdate as the TTL when available; fall back to
  // the 7-day default when it's missing or parsing fails.
  let ttl = kdsCache.TTL_CRL_SECONDS;
  const nextUpdate = parseCrlNextUpdate(der);
  if (nextUpdate) {
    const seconds = Math.floor((nextUpdate.getTime() - Date.now()) / 1000);
    if (seconds > 0) ttl = seconds;
  }

  kdsCache.put("crl", product, der, ttl);
  return der;
}

/** Return true if the VCEK is NOT in the CRL (i.e. not revoked). */
function checkVcekRevocation(vcekDer: Buffer, crlDer: Buffer): boolean {
  const cert = new crypto.X509Certificate(vcekDer);
  const vcekSerial = normalizeSerialHex(cert.serialNumber);
  const crl = qvlUtils.CertificateList.decode(crlDer, "der");
  const revokedList = crl?.tbsCertList?.revokedCertificates ?? [];
  for (const entry of revokedList) {
    const serial = normalizeSerialHex(entry.userCertificate.toString(16));
    if (serial === vcekSerial) return false;
  }
  return true;
}

function splitPem(pem: string): string[] {
  const blocks: string[] = [];
  const re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem)) !== null) {
    blocks.push(m[0]);
  }
  return blocks;
}

/**
 * Pinned SHA-256 fingerprints of the AMD ARK public keys (SPKI), per product.
 *
 * AMD publishes the ARK at `https://kdsintf.amd.com/vcek/v1/{product}/cert_chain`,
 * but the chain endpoint is reachable over the public internet — without
 * pinning, a DNS-spoof or compromised KDS could substitute a self-signed
 * impostor ARK and the chain check would still pass. These fingerprints are
 * the cryptographic anchor that ties the chain to AMD.
 *
 * The pin is over the SubjectPublicKeyInfo (not the cert envelope) so it
 * survives certificate reissuance with the same key. ARKs ship with 25-year
 * validity (e.g. ARK-Milan: 2020 → 2045).
 *
 * Recompute by running:
 *   curl -sf https://kdsintf.amd.com/vcek/v1/{product}/cert_chain |
 *     awk '/-----BEGIN CERTIFICATE-----/{n++} n==2{print}' |
 *     openssl x509 -pubkey -noout |
 *     openssl pkey -pubin -outform DER 2>/dev/null |
 *     openssl dgst -sha256
 */
const PINNED_ARK_SPKI_SHA256: Record<string, string> = {
  Milan: "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9",
  Genoa: "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831",
  Turin: "4f125410563a2ab9a50356f9243f6fe0b6f73de98603f53f90339c70e9d7ad08",
};

function spkiSha256Hex(cert: crypto.X509Certificate): string {
  const spkiDer = cert.publicKey.export({ format: "der", type: "spki" });
  return crypto.createHash("sha256").update(spkiDer).digest("hex");
}

/** Verify VCEK → ASK → ARK certificate chain and pin the ARK to AMD. */
function verifyCertChain(
  vcekDer: Buffer,
  chainPem: string,
  product: string,
): boolean {
  const blocks = splitPem(chainPem);
  if (blocks.length < 2) {
    return false;
  }

  const vcek = new crypto.X509Certificate(vcekDer);
  const ask = new crypto.X509Certificate(blocks[0]!);
  const ark = new crypto.X509Certificate(blocks[1]!);

  const now = new Date();

  // Check validity periods
  for (const cert of [vcek, ask, ark]) {
    if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) {
      return false;
    }
  }

  // Pin the ARK to the known AMD root for this product. Without this,
  // a self-signed impostor chain would pass the cryptographic checks below.
  const expectedArkSpki = PINNED_ARK_SPKI_SHA256[product];
  if (!expectedArkSpki) return false;
  if (spkiSha256Hex(ark) !== expectedArkSpki) return false;

  try {
    // X509Certificate.verify() handles RSA-PSS and ECDSA automatically
    // ARK is self-signed
    if (!ark.verify(ark.publicKey)) return false;
    // ASK signed by ARK
    if (!ask.verify(ark.publicKey)) return false;
    // VCEK signed by ASK
    if (!vcek.verify(ask.publicKey)) return false;
    return true;
  } catch {
    return false;
  }
}

function verifyReportSignature(
  rpt: ReturnType<typeof parseReport>,
  vcekDer: Buffer,
): boolean {
  const signedData = rpt.rawReport.subarray(0, SIG_OFFSET);
  const r = BigInt("0x" + Buffer.from(rpt.signatureR).reverse().toString("hex"));
  const s = BigInt("0x" + Buffer.from(rpt.signatureS).reverse().toString("hex"));
  if (r === 0n && s === 0n) return false;

  const derSig = ecdsaLeRsToDer(rpt.signatureR, rpt.signatureS);

  // Import VCEK public key from DER certificate
  const cert = new crypto.X509Certificate(vcekDer);
  const pubKey = cert.publicKey;

  const verifier = crypto.createVerify("SHA384");
  verifier.update(signedData);
  try {
    return verifier.verify({ key: pubKey, dsaEncoding: "der" }, derSig);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Public
// ---------------------------------------------------------------------------

export async function checkSevCpuAttestation(
  dataOrUrl: string,
  product = "",
  reloadAmdKds = false,
  strict = false,
): Promise<AttestationResult> {
  const data = isVmUrl(dataOrUrl) ? await fetchCpuQuote(dataOrUrl) : dataOrUrl;
  const errors: string[] = [];
  const checks: Record<string, boolean> = {};

  // Decode input (try hex, then base64)
  let raw: Buffer;
  let rpt: ReturnType<typeof parseReport>;
  try {
    const text = data.trim();
    try {
      raw = Buffer.from(text, "hex");
      // Verify it's plausible hex (hex decode doesn't throw on bad input in Node)
      if (raw.length < REPORT_SIZE && text.length > raw.length * 2) {
        throw new Error("not hex");
      }
    } catch {
      raw = Buffer.from(text, "base64");
    }
    rpt = parseReport(raw);
    checks.report_parsed = true;
  } catch (e: any) {
    return makeResult("SEV-SNP", {
      checks: { report_parsed: false },
      errors: [e.message],
    });
  }

  // Fetch VCEK
  let vcekDer: Buffer;
  let detectedProduct: string;
  try {
    const result = await fetchVcek(product, rpt.chipId, rpt.reportedTcb, reloadAmdKds, strict);
    vcekDer = result.der;
    detectedProduct = result.product;
    checks.vcek_fetched = true;
  } catch (e: any) {
    errors.push(`Failed to fetch VCEK: ${e.message}`);
    checks.vcek_fetched = false;
    return makeResult("SEV-SNP", { checks, errors });
  }

  // Verify cert chain (VCEK -> ASK -> ARK)
  try {
    const chainPem = await fetchChainPem(detectedProduct, reloadAmdKds, strict);
    checks.cert_chain_valid = verifyCertChain(vcekDer, chainPem, detectedProduct);
    if (!checks.cert_chain_valid) {
      errors.push(
        "Certificate chain verification failed (VCEK → ASK → ARK)",
      );
    }
  } catch (e: any) {
    checks.cert_chain_valid = false;
    errors.push(`Failed to verify cert chain: ${e.message}`);
  }

  // CRL revocation check — fetch the AMD VCEK CRL and confirm the leaf
  // cert's serial number is not in the revoked list. Cached for 7 days.
  try {
    const crlDer = await fetchCrl(detectedProduct, reloadAmdKds, strict);
    checks.crl_check_passed = checkVcekRevocation(vcekDer, crlDer);
    if (!checks.crl_check_passed) {
      const cert = new crypto.X509Certificate(vcekDer);
      errors.push(
        `VCEK serial ${cert.serialNumber} is revoked per AMD CRL`,
      );
    }
  } catch (e: any) {
    checks.crl_check_passed = false;
    errors.push(`CRL revocation check failed: ${e.message}`);
  }

  // Verify report signature
  checks.report_signature_valid = verifyReportSignature(rpt, vcekDer);
  if (!checks.report_signature_valid) {
    errors.push("Report signature verification failed");
  }

  const valid =
    !!checks.report_parsed &&
    !!checks.vcek_fetched &&
    !!checks.cert_chain_valid &&
    !!checks.crl_check_passed &&
    !!checks.report_signature_valid;

  const report: Record<string, any> = {
    version: rpt.version,
    guest_svn: rpt.guestSvn,
    vmpl: rpt.vmpl,
    policy: `0x${rpt.policy.toString(16).padStart(16, "0")}`,
    smt_allowed: rpt.smtAllowed,
    debug_allowed: rpt.debugAllowed,
    family_id: rpt.familyId.toString("hex"),
    image_id: rpt.imageId.toString("hex"),
    measurement: rpt.measurement.toString("hex"),
    report_data: rpt.reportData.toString("hex"),
    host_data: rpt.hostData.toString("hex"),
    id_key_digest: rpt.idKeyDigest.toString("hex"),
    author_key_digest: rpt.authorKeyDigest.toString("hex"),
    report_id: rpt.reportId.toString("hex"),
    chip_id: rpt.chipId.toString("hex"),
    current_tcb: rpt.currentTcb,
    reported_tcb: rpt.reportedTcb,
    committed_tcb: rpt.committedTcb,
    launch_tcb: rpt.launchTcb,
    current_firmware: `${rpt.currentMajor}.${rpt.currentMinor} (build ${rpt.currentBuild})`,
    platform_info: `0x${rpt.platformInfo.toString(16).padStart(16, "0")}`,
    product: detectedProduct,
  };

  return makeResult("SEV-SNP", { valid, checks, report, errors });
}
