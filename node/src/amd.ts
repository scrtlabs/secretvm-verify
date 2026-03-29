import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { AttestationResult, makeResult } from "./types.js";

const AMD_KDS_BASE = "https://kdsintf.amd.com";
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

async function fetchVcek(
  product: string,
  chipId: Buffer,
  reportedTcb: TcbVersion,
): Promise<{ der: Buffer; product: string }> {
  const candidates = product ? [product] : ["Genoa", "Milan", "Turin"];
  for (const name of candidates) {
    const url = vcekUrl(name, chipId, reportedTcb);
    const resp = await fetch(url);
    if (resp.ok) {
      const der = Buffer.from(await resp.arrayBuffer());
      return { der, product: name };
    }
    if (resp.status === 429) {
      throw new Error(
        "AMD KDS rate-limited (429). Retry later or specify product.",
      );
    }
    if (product) {
      throw new Error(`AMD KDS returned ${resp.status}`);
    }
  }
  throw new Error(
    "Could not fetch VCEK for any known product (Genoa/Milan/Turin)",
  );
}

async function fetchChainPem(product: string): Promise<string> {
  const url = `${AMD_KDS_BASE}/vcek/v1/${product}/cert_chain`;
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`AMD KDS cert_chain returned ${resp.status}`);
  }
  return await resp.text();
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

/** Verify VCEK → ASK → ARK chain using openssl CLI. */
function verifyCertChainOpenssl(vcekDer: Buffer, chainPem: string): boolean {
  const td = mkdtempSync(join(tmpdir(), "amd-"));
  try {
    // Convert VCEK DER to PEM
    const vcekPem = execFileSync("openssl", [
      "x509",
      "-inform",
      "DER",
      "-outform",
      "PEM",
    ], { input: vcekDer }).toString();
    const vcekPath = join(td, "vcek.pem");
    writeFileSync(vcekPath, vcekPem);

    const blocks = splitPem(chainPem);
    if (blocks.length < 2) {
      throw new Error(
        `Expected at least 2 certs in chain, got ${blocks.length}`,
      );
    }

    const askPath = join(td, "ask.pem");
    const arkPath = join(td, "ark.pem");
    writeFileSync(askPath, blocks[0]!);
    writeFileSync(arkPath, blocks[1]!);

    try {
      execFileSync("openssl", [
        "verify",
        "-CAfile",
        arkPath,
        "-untrusted",
        askPath,
        vcekPath,
      ]);
      return true;
    } catch {
      return false;
    }
  } finally {
    rmSync(td, { recursive: true, force: true });
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

export async function checkAmdCpuAttestation(
  data: string,
  product = "",
): Promise<AttestationResult> {
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
    const result = await fetchVcek(product, rpt.chipId, rpt.reportedTcb);
    vcekDer = result.der;
    detectedProduct = result.product;
    checks.vcek_fetched = true;
  } catch (e: any) {
    errors.push(`Failed to fetch VCEK: ${e.message}`);
    checks.vcek_fetched = false;
    return makeResult("SEV-SNP", { checks, errors });
  }

  // Verify cert chain
  try {
    const chainPem = await fetchChainPem(detectedProduct);
    checks.cert_chain_valid = verifyCertChainOpenssl(vcekDer, chainPem);
    if (!checks.cert_chain_valid) {
      errors.push(
        "Certificate chain verification failed (VCEK → ASK → ARK)",
      );
    }
  } catch (e: any) {
    checks.cert_chain_valid = false;
    errors.push(`Failed to verify cert chain: ${e.message}`);
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
