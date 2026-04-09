/**
 * Intel TDX attestation verification.
 *
 * Cryptographic verification (PCK chain, QE Identity, CRLs, TCB Info, quote
 * signature) is delegated to the upstream `@teekit/qvl` library, which
 * implements the full Intel DCAP quote verification flow against a pinned
 * Intel SGX Root CA. This module's job is to assemble the collateral
 * (CRLs + TCB lookup callback) from PCCS, parse the quote so we can populate
 * report fields, and hand off to teekit/qvl for the actual crypto.
 */

import { verifyTdx, getTcbStatus, isTcbInfoFresh } from "@teekit/qvl";
import { AttestationResult, makeResult } from "./types.js";
import { isVmUrl, fetchCpuQuote } from "./url.js";

const PCCS_HOST = "https://pccs.scrtlabs.com";

// ---------------------------------------------------------------------------
// Collateral fetching helpers
// ---------------------------------------------------------------------------

/**
 * Decode hex-ASCII to raw bytes if `b` looks like hex-encoded ASN.1 DER.
 *
 * The SCRT PCCS deployment returns CRLs as hex-encoded ASCII (e.g.
 * b'30820122...') instead of raw DER. teekit/qvl reads the body as raw bytes
 * and chokes on the unexpected encoding. This helper detects hex-ASCII and
 * decodes it. Other PCCS deployments return raw DER, in which case the
 * decode either fails or doesn't begin with an ASN.1 SEQUENCE tag, and we
 * pass the bytes through unchanged.
 */
function maybeDehex(b: Uint8Array): Uint8Array {
  if (b.length % 2 !== 0) return b;
  try {
    const text = Buffer.from(b).toString("ascii");
    if (!/^[0-9a-fA-F]+$/.test(text)) return b;
    const decoded = Buffer.from(text, "hex");
    if (decoded.length > 0 && decoded[0] === 0x30) return decoded;
  } catch {
    /* fall through */
  }
  return b;
}

/** Fetch the three CRLs needed for full PCK chain revocation checks. */
async function fetchCrls(host: string): Promise<Uint8Array[]> {
  const urls = [
    `${host}/sgx/certification/v4/pckcrl?ca=processor`,
    `${host}/sgx/certification/v4/pckcrl?ca=platform`,
    `${host}/sgx/certification/v4/rootcacrl`,
  ];
  const results = await Promise.all(
    urls.map(async (url) => {
      const resp = await fetch(url);
      if (!resp.ok) {
        throw new Error(`PCCS ${url} returned ${resp.status}`);
      }
      const buf = new Uint8Array(await resp.arrayBuffer());
      return maybeDehex(buf);
    }),
  );
  return results;
}

/** Captured TCB info — populated by the verifyTcb callback during verification. */
interface TcbCapture {
  status: string;
  advisoryIds: string[];
  fresh: boolean;
}

/**
 * Build a verifyTcb callback that hits the supplied PCCS host, derives the
 * TCB status using teekit's helper, and captures the result for inclusion in
 * the AttestationResult report.
 */
function makeVerifyTcbCallback(host: string, capture: TcbCapture) {
  return async ({
    fmspc,
    cpuSvn,
    pceSvn,
    quote,
  }: {
    fmspc: string;
    cpuSvn: number[];
    pceSvn: number;
    quote: any;
  }): Promise<boolean> => {
    const isTdx = quote?.header?.tee_type === 0x81;
    const path = isTdx ? "tdx" : "sgx";
    const url = `${host}/${path}/certification/v4/tcb?fmspc=${fmspc}`;
    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`PCCS ${url} returned ${resp.status}`);
    }
    const tcbInfo = (await resp.json()) as any;
    const status = getTcbStatus(tcbInfo, cpuSvn, pceSvn, isTdx);
    const fresh = isTcbInfoFresh(tcbInfo, Date.now());
    capture.status = status;
    capture.fresh = fresh;
    // Walk the levels to find the matching one and pull its advisoryIDs
    for (const level of tcbInfo.tcbInfo?.tcbLevels ?? []) {
      const components: { svn: number }[] = isTdx
        ? level.tcb?.tdxtcbcomponents ?? []
        : level.tcb?.sgxtcbcomponents ?? [];
      let match = true;
      for (let i = 0; i < components.length; i++) {
        if (i < cpuSvn.length && cpuSvn[i]! < (components[i]?.svn ?? 0)) {
          match = false;
          break;
        }
      }
      if (match && (level.tcb?.pcesvn === undefined || pceSvn >= level.tcb.pcesvn)) {
        capture.advisoryIds = level.advisoryIDs ?? [];
        break;
      }
    }
    return (
      fresh && (status === "UpToDate" || status === "ConfigurationNeeded")
    );
  };
}

/**
 * Run full DCAP-grade quote verification via @teekit/qvl. Throws on any
 * cryptographic failure with a descriptive error message; returns the
 * captured TCB status / advisory IDs on success.
 */
async function qvlVerifyTdx(
  rawQuote: Uint8Array,
): Promise<TcbCapture> {
  const crls = await fetchCrls(PCCS_HOST);
  const capture: TcbCapture = {
    status: "Unknown",
    advisoryIds: [],
    fresh: false,
  };
  const config = {
    crls,
    verifyTcb: makeVerifyTcbCallback(PCCS_HOST, capture),
    verifyMeasurements: () => true, // accept any measurements — caller checks separately
  };
  const ok = await verifyTdx(rawQuote, config);
  if (!ok) {
    // verifyTdx returns false (rather than throws) only when verifyTcb rejects
    throw new Error(
      `TCB rejected: status=${capture.status}, fresh=${capture.fresh}`,
    );
  }
  return capture;
}

// ---------------------------------------------------------------------------
// FMSPC extraction (used to populate report.fmspc)
// ---------------------------------------------------------------------------

import nodeCrypto from "node:crypto";

function extractFmspc(certPem: string): string | null {
  try {
    const cert = new nodeCrypto.X509Certificate(certPem);
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
  } catch {
    /* fall through */
  }
  return null;
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

  // Parse — needed to populate report fields and extract fmspc
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

  // Best-effort fmspc extraction for the report — failure is non-fatal.
  let fmspc: string | null = null;
  if (q.certDataType === 5 || q.certDataType === 6) {
    const certText = q.certData.toString("ascii");
    const m = certText.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/,
    );
    if (m) fmspc = extractFmspc(m[0]);
  }

  // Full DCAP verification via @teekit/qvl
  let tcbStatus = "Unknown";
  let advisoryIds: string[] = [];
  try {
    const capture = await qvlVerifyTdx(new Uint8Array(raw));
    checks.quote_verified = true;
    tcbStatus = capture.status;
    advisoryIds = capture.advisoryIds;
  } catch (e: any) {
    checks.quote_verified = false;
    errors.push(`Quote verification failed: ${e.message}`);
  }

  const valid = !!checks.quote_parsed && !!checks.quote_verified;

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
    fmspc: fmspc ?? "",
    tcb_status: tcbStatus,
    advisory_ids: advisoryIds,
  };

  return makeResult("TDX", { valid, checks, report, errors });
}

// ---------------------------------------------------------------------------
// Quote parser (internal — kept because parseTdxQuoteFields below is exported
// and consumed by workload.ts for measurement extraction without verification)
// ---------------------------------------------------------------------------

function readU16LE(buf: Buffer, off: number): number {
  return buf.readUInt16LE(off);
}

function readU32LE(buf: Buffer, off: number): number {
  return buf.readUInt32LE(off);
}

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

  if (version !== 4) throw new Error(`Unsupported quote version: ${version}`);
  if (teeType !== 0x81)
    throw new Error(`Not a TDX quote (tee_type=0x${teeType.toString(16)})`);

  // TD Report Body: 584 bytes at offset 48
  const off = 48;
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

  // Signature data at offset 632 (just enough to find certData for fmspc)
  let soff = 636 + 64 + 64; // skip sig_data_len(4) + quote_sig(64) + att_pub_key(64)
  const outerCertType = readU16LE(raw, soff);
  soff += 2;
  const outerCertSize = readU32LE(raw, soff);
  soff += 4;
  const outerCertData = raw.subarray(soff, soff + outerCertSize);

  let certDataType: number;
  let certData: Buffer;
  if (outerCertType === 6) {
    let c = 384 + 64; // skip qe_report(384) + qe_report_sig(64)
    const qaLen = readU16LE(outerCertData, c);
    c += 2 + qaLen; // skip qe_auth_data
    certDataType = readU16LE(outerCertData, c);
    c += 2;
    const cdLen = readU32LE(outerCertData, c);
    c += 4;
    certData = outerCertData.subarray(c, c + cdLen);
  } else {
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
    td,
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
