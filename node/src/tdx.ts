import crypto from "node:crypto";
import { AttestationResult, makeResult } from "./types.js";
import { isVmUrl, fetchCpuQuote } from "./url.js";

const INTEL_PCS_BASE =
    "https://pccs.scrtlabs.com/sgx/certification/v4";
// "https://api.trustedservices.intel.com/sgx/certification/v4";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readU16LE(buf: Buffer, off: number): number {
  return buf.readUInt16LE(off);
}

function readU32LE(buf: Buffer, off: number): number {
  return buf.readUInt32LE(off);
}

/** Verify ECDSA-P256-SHA256 with raw 64-byte pubkey and 64-byte R||S sig. */
function verifyEcdsaP256(
  pubKeyRaw: Buffer,
  message: Buffer,
  sigRaw: Buffer,
): boolean {
  // Build uncompressed point: 0x04 || X(32) || Y(32)
  const uncompressed = Buffer.concat([Buffer.from([0x04]), pubKeyRaw]);
  const key = crypto.createPublicKey({
    key: Buffer.concat([
      // DER header for EC P-256 uncompressed point
      Buffer.from(
        "3059301306072a8648ce3d020106082a8648ce3d030107034200",
        "hex",
      ),
      uncompressed,
    ]),
    format: "der",
    type: "spki",
  });

  // Convert R||S to DER signature
  const r = sigRaw.subarray(0, 32);
  const s = sigRaw.subarray(32, 64);
  const derSig = ecdsaRsToDer(r, s);

  const verifier = crypto.createVerify("SHA256");
  verifier.update(message);
  try {
    return verifier.verify({ key, dsaEncoding: "der" }, derSig);
  } catch {
    return false;
  }
}

/** Convert raw R, S buffers to DER-encoded ECDSA signature. */
function ecdsaRsToDer(r: Buffer, s: Buffer): Buffer {
  function encodeInt(v: Buffer): Buffer {
    // Strip leading zeros but keep one if high bit set
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
  return Buffer.concat([
    Buffer.from([0x30, ri.length + si.length]),
    ri,
    si,
  ]);
}

// ---------------------------------------------------------------------------
// PEM cert helpers
// ---------------------------------------------------------------------------

function extractPemCerts(pem: string): crypto.X509Certificate[] {
  const certs: crypto.X509Certificate[] = [];
  const re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem)) !== null) {
    certs.push(new crypto.X509Certificate(m[0]));
  }
  return certs;
}

function verifyCertChain(certs: crypto.X509Certificate[]): boolean {
  for (let i = 0; i < certs.length - 1; i++) {
    if (!certs[i]!.checkIssued(certs[i + 1]!)) return false;
    try {
      if (!certs[i]!.verify(certs[i + 1]!.publicKey)) return false;
    } catch {
      return false;
    }
  }
  if (certs.length > 0) {
    const root = certs[certs.length - 1]!;
    try {
      if (!root.verify(root.publicKey)) return false;
    } catch {
      return false;
    }
  }
  return true;
}

function extractFmspc(cert: crypto.X509Certificate): string | null {
  // Parse the raw DER to find FMSPC OID 1.2.840.113741.1.13.1.4
  const raw = Buffer.from(cert.raw);
  const fmspcOid = Buffer.from("060a2a864886f84d010d0104", "hex");
  const idx = raw.indexOf(fmspcOid);
  if (idx < 0) return null;
  const searchStart = idx + fmspcOid.length;
  for (let j = searchStart; j < Math.min(searchStart + 20, raw.length - 6); j++) {
    if (raw[j] === 0x04 && raw[j + 1] === 0x06) {
      return raw.subarray(j + 2, j + 8).toString("hex");
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// TCB status
// ---------------------------------------------------------------------------

async function fetchTcbStatus(
  fmspc: string,
  teeTcbSvn: Buffer,
): Promise<string> {
  const url = `${INTEL_PCS_BASE}/tcb?fmspc=${fmspc}&type=TDX`;
  const resp = await fetch(url);
  if (!resp.ok) return `PCS returned ${resp.status}`;
  const body = (await resp.json()) as any;
  const tcbInfo = body.tcbInfo ?? body;
  for (const level of tcbInfo.tcbLevels ?? []) {
    const tdxComponents: { svn: number }[] =
      level.tcb?.tdxtcbcomponents ?? [];
    let match = true;
    for (let i = 0; i < tdxComponents.length; i++) {
      if (i < teeTcbSvn.length && teeTcbSvn[i]! < (tdxComponents[i]?.svn ?? 0)) {
        match = false;
        break;
      }
    }
    if (match) {
      const status: string = level.tcbStatus ?? "Unknown";
      const date: string = level.tcbDate ?? "";
      return date ? `${status} (as of ${date})` : status;
    }
  }
  return "OutOfDate (no matching TCB level found)";
}

// ---------------------------------------------------------------------------
// Public
// ---------------------------------------------------------------------------

export async function checkTdxCpuAttestation(
  dataOrUrl: string,
): Promise<AttestationResult> {
  const data = isVmUrl(dataOrUrl) ? await fetchCpuQuote(dataOrUrl) : dataOrUrl;
  const errors: string[] = [];
  const checks: Record<string, boolean> = {};

  // Parse
  let raw: Buffer;
  let q: ReturnType<typeof parseQuote>;
  try {
    raw = Buffer.from(data.trim(), "hex");
    q = parseQuote(raw);
    checks.quote_parsed = true;
  } catch (e: any) {
    return makeResult("TDX", {
      checks: { quote_parsed: false },
      errors: [e.message],
    });
  }

  const td = q.td;

  // Cert chain
  if (q.certDataType !== 5 && q.certDataType !== 6) {
    errors.push(`Unsupported cert data type: ${q.certDataType}`);
    checks.cert_chain_valid = false;
  } else {
    const certs = extractPemCerts(q.certData.toString("ascii"));
    if (certs.length < 2) {
      errors.push(`Expected at least 2 certificates, got ${certs.length}`);
      checks.cert_chain_valid = false;
    } else {
      checks.cert_chain_valid = verifyCertChain(certs);
      if (!checks.cert_chain_valid) {
        errors.push("PCK certificate chain signature verification failed");
      }

      // QE Report Signature
      const pckPubKey = certs[0]!.publicKey;
      const qeSigDer = ecdsaRsToDer(
        q.qeReportSignature.subarray(0, 32),
        q.qeReportSignature.subarray(32, 64),
      );
      try {
        const v = crypto.createVerify("SHA256");
        v.update(q.qeReport);
        checks.qe_report_signature_valid = v.verify(
          { key: pckPubKey, dsaEncoding: "der" },
          qeSigDer,
        );
      } catch {
        checks.qe_report_signature_valid = false;
      }
      if (!checks.qe_report_signature_valid) {
        errors.push("QE Report signature verification failed");
      }

      // Attestation key binding
      const attKeyHash = crypto
        .createHash("sha256")
        .update(q.attestationPubKey)
        .update(q.qeAuthData)
        .digest();
      const qeReportData = q.qeReport.subarray(320, 384);
      checks.attestation_key_bound = qeReportData
        .subarray(0, 32)
        .equals(attKeyHash);
      if (!checks.attestation_key_bound) {
        errors.push(
          "Attestation key hash does not match QE Report REPORTDATA",
        );
      }

      // FMSPC
      var fmspc = extractFmspc(certs[0]!);
    }
  }

  if (!checks.cert_chain_valid) {
    checks.qe_report_signature_valid ??= false;
    checks.attestation_key_bound = false;
  }

  // Quote signature
  const signedData = Buffer.concat([q.rawHeader, q.rawTdReport]);
  checks.quote_signature_valid = verifyEcdsaP256(
    q.attestationPubKey,
    signedData,
    q.quoteSignature,
  );
  if (!checks.quote_signature_valid) {
    errors.push("Quote signature verification failed");
  }

  // TCB status
  let tcbStatus = "Unknown";
  if (fmspc!) {
    try {
      tcbStatus = await fetchTcbStatus(fmspc!, td.teeTcbSvn);
    } catch (e: any) {
      tcbStatus = `Could not fetch: ${e.message}`;
    }
  }

  const valid =
    !!checks.quote_parsed &&
    !!checks.cert_chain_valid &&
    !!checks.qe_report_signature_valid &&
    !!checks.attestation_key_bound &&
    !!checks.quote_signature_valid;

  const report: Record<string, any> = {
    version: q.version,
    att_key_type: q.attKeyType,
    tee_type: q.teeType,
    qe_svn: q.qeSvn,
    pce_svn: q.pceSvn,
    qe_vendor_id: q.qeVendorId.toString("hex"),
    tee_tcb_svn: td.teeTcbSvn.toString("hex"),
    mr_seam: td.mrSeam.toString("hex"),
    mr_td: td.mrTd.toString("hex"),
    mr_config_id: td.mrConfigId.toString("hex"),
    mr_owner: td.mrOwner.toString("hex"),
    mr_owner_config: td.mrOwnerConfig.toString("hex"),
    rt_mr0: td.rtMr0.toString("hex"),
    rt_mr1: td.rtMr1.toString("hex"),
    rt_mr2: td.rtMr2.toString("hex"),
    rt_mr3: td.rtMr3.toString("hex"),
    report_data: td.reportData.toString("hex"),
    td_attributes: td.tdAttributes.toString("hex"),
    xfam: td.xfam.toString("hex"),
    fmspc: fmspc! ?? "",
    tcb_status: tcbStatus,
  };

  return makeResult("TDX", { valid, checks, report, errors });
}

// ---------------------------------------------------------------------------
// Quote parser (internal)
// ---------------------------------------------------------------------------

function parseQuote(raw: Buffer) {
  if (raw.length < 632) {
    throw new Error(`Quote too short: ${raw.length} bytes (minimum 632)`);
  }

  const version = readU16LE(raw, 0);
  const attKeyType = readU16LE(raw, 2);
  const teeType = readU32LE(raw, 4);
  const qeSvn = readU16LE(raw, 8);
  const pceSvn = readU16LE(raw, 10);
  const qeVendorId = raw.subarray(12, 28);
  const userData = raw.subarray(28, 48);
  const rawHeader = raw.subarray(0, 48);

  if (version !== 4) throw new Error(`Unsupported quote version: ${version}`);
  if (teeType !== 0x81)
    throw new Error(`Not a TDX quote (tee_type=0x${teeType.toString(16)})`);

  // TD Report Body: 584 bytes at offset 48
  const off = 48;
  const rawTdReport = raw.subarray(off, off + 584);
  const td = {
    teeTcbSvn: raw.subarray(off, off + 16),
    mrSeam: raw.subarray(off + 16, off + 64),
    mrSignerSeam: raw.subarray(off + 64, off + 112),
    seamAttributes: raw.subarray(off + 112, off + 120),
    tdAttributes: raw.subarray(off + 120, off + 128),
    xfam: raw.subarray(off + 128, off + 136),
    mrTd: raw.subarray(off + 136, off + 184),
    mrConfigId: raw.subarray(off + 184, off + 232),
    mrOwner: raw.subarray(off + 232, off + 280),
    mrOwnerConfig: raw.subarray(off + 280, off + 328),
    rtMr0: raw.subarray(off + 328, off + 376),
    rtMr1: raw.subarray(off + 376, off + 424),
    rtMr2: raw.subarray(off + 424, off + 472),
    rtMr3: raw.subarray(off + 472, off + 520),
    reportData: raw.subarray(off + 520, off + 584),
  };

  // Signature data at offset 632
  let soff = 636; // skip 4-byte sig_data_len
  const quoteSignature = raw.subarray(soff, soff + 64);
  soff += 64;
  const attestationPubKey = raw.subarray(soff, soff + 64);
  soff += 64;

  const outerCertType = readU16LE(raw, soff);
  soff += 2;
  const outerCertSize = readU32LE(raw, soff);
  soff += 4;
  const outerCertData = raw.subarray(soff, soff + outerCertSize);

  let qeReport: Buffer;
  let qeReportSignature: Buffer;
  let qeAuthData: Buffer;
  let certDataType: number;
  let certData: Buffer;

  if (outerCertType === 6) {
    let c = 0;
    qeReport = outerCertData.subarray(c, c + 384);
    c += 384;
    qeReportSignature = outerCertData.subarray(c, c + 64);
    c += 64;
    const qaLen = readU16LE(outerCertData, c);
    c += 2;
    qeAuthData = outerCertData.subarray(c, c + qaLen);
    c += qaLen;
    certDataType = readU16LE(outerCertData, c);
    c += 2;
    const cdLen = readU32LE(outerCertData, c);
    c += 4;
    certData = outerCertData.subarray(c, c + cdLen);
  } else {
    qeReport = outerCertData.subarray(0, 384);
    qeReportSignature = outerCertData.subarray(384, 448);
    let c = 448;
    const qaLen = readU16LE(outerCertData, c);
    c += 2;
    qeAuthData = outerCertData.subarray(c, c + qaLen);
    c += qaLen;
    certDataType = outerCertType;
    certData = outerCertData;
  }

  return {
    version,
    attKeyType,
    teeType,
    qeSvn,
    pceSvn,
    qeVendorId,
    userData,
    rawHeader,
    td,
    rawTdReport,
    quoteSignature,
    attestationPubKey,
    qeReport,
    qeReportSignature,
    qeAuthData,
    certDataType,
    certData,
  };
}

// ---------------------------------------------------------------------------
// Exported quote field extractor (no network calls)
// ---------------------------------------------------------------------------

export interface TdxQuoteFields {
  mrtd: string;
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
}

/** Parse a raw TDX quote (hex-encoded) and return measurement fields only. */
export function parseTdxQuoteFields(data: string): TdxQuoteFields {
  const raw = Buffer.from(data.trim(), "hex");
  const q = parseQuote(raw);
  return {
    mrtd: q.td.mrTd.toString("hex"),
    rtmr0: q.td.rtMr0.toString("hex"),
    rtmr1: q.td.rtMr1.toString("hex"),
    rtmr2: q.td.rtMr2.toString("hex"),
    rtmr3: q.td.rtMr3.toString("hex"),
  };
}
