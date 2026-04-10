import { AttestationResult, makeResult } from "./types.js";
import { checkTdxCpuAttestation } from "./tdx.js";
import { checkSevCpuAttestation } from "./amd.js";
import { isVmUrl, fetchCpuQuote } from "./url.js";

/**
 * Detect whether the quote is Intel TDX (hex) or AMD SEV-SNP (base64).
 */
export function detectCpuQuoteType(data: string): "TDX" | "SEV-SNP" | "unknown" {
  const text = data.trim();

  // Try hex — TDX quotes: version=4, tee_type=0x81
  try {
    const buf = Buffer.from(text, "hex");
    if (buf.length >= 8) {
      const version = buf.readUInt16LE(0);
      const teeType = buf.readUInt32LE(4);
      if (version === 4 && teeType === 0x81) return "TDX";
    }
  } catch {
    // not hex
  }

  // Try base64 — AMD SEV-SNP: version >= 2, sig_algo == 1
  try {
    const buf = Buffer.from(text, "base64");
    if (buf.length >= 0x38) {
      const version = buf.readUInt32LE(0);
      const sigAlgo = buf.readUInt32LE(0x034);
      if (version >= 2 && version <= 4 && sigAlgo === 1) return "SEV-SNP";
    }
  } catch {
    // not base64
  }

  return "unknown";
}

/**
 * Verify a CPU attestation quote, auto-detecting Intel TDX vs AMD SEV-SNP.
 *
 * @param reloadAmdKds If true, bypass the local AMD KDS cache and re-fetch
 *   VCEK / cert chain / CRL. No effect on the TDX path (which doesn't cache).
 */
export async function checkCpuAttestation(
  dataOrUrl: string,
  product = "",
  reloadAmdKds = false,
): Promise<AttestationResult> {
  const data = isVmUrl(dataOrUrl) ? await fetchCpuQuote(dataOrUrl) : dataOrUrl;
  const quoteType = detectCpuQuoteType(data);

  if (quoteType === "TDX") {
    return checkTdxCpuAttestation(data);
  }
  if (quoteType === "SEV-SNP") {
    return checkSevCpuAttestation(data, product, reloadAmdKds);
  }

  return makeResult("unknown", {
    errors: [
      "Could not detect quote type (expected hex-encoded TDX or base64-encoded SEV-SNP)",
    ],
  });
}
