import crypto from "node:crypto";
import tls from "node:tls";

const SECRET_VM_PORT = 29343;

/**
 * Detect whether a string is a VM URL rather than raw quote data.
 * URLs contain dots, no whitespace/newlines, and are short.
 */
export function isVmUrl(data: string): boolean {
  const s = data.trim();
  if (s.startsWith("https://") || s.startsWith("http://")) return true;
  return s.includes(".") && !s.includes(" ") && !s.includes("\n") && s.length < 256;
}

/**
 * Fetch data from a VM endpoint.
 * Accepts bare hostnames, host:port, or full URLs.
 */
export async function fetchVmEndpoint(url: string, endpoint: string): Promise<string> {
  let u = url.trim();
  if (!u.includes("://")) u = `https://${u}`;
  const parsed = new URL(u);
  const port = parsed.port || SECRET_VM_PORT;
  const base = `https://${parsed.hostname}:${port}`;
  const resp = await fetch(`${base}/${endpoint}`);
  if (!resp.ok) throw new Error(`HTTP ${resp.status} from ${base}/${endpoint}`);
  return resp.text();
}

/**
 * Fetch CPU quote from a VM.
 */
export async function fetchCpuQuote(url: string): Promise<string> {
  return fetchVmEndpoint(url, "cpu");
}

/**
 * Fetch GPU attestation from a VM.
 */
export async function fetchGpuQuote(url: string): Promise<string> {
  return fetchVmEndpoint(url, "gpu");
}

/**
 * Fetch docker-compose from a VM, stripping HTML wrapping.
 */
export async function fetchDockerCompose(url: string): Promise<string> {
  const raw = await fetchVmEndpoint(url, "docker-compose");
  return extractDockerCompose(raw);
}

export function getTlsCertFingerprint(
  host: string,
  port: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, rejectUnauthorized: true },
      () => {
        const cert = socket.getPeerX509Certificate();
        if (!cert) {
          socket.destroy();
          return reject(new Error("No certificate received"));
        }
        const fingerprint = crypto
          .createHash("sha256")
          .update(cert.raw)
          .digest();
        socket.destroy();
        resolve(fingerprint);
      },
    );
    socket.on("error", reject);
    socket.setTimeout(10_000, () => {
      socket.destroy();
      reject(new Error("TLS connection timed out"));
    });
  });
}

export function extractDockerCompose(raw: string): string {
  let text = raw.trim();
  const preMatch = text.match(/<pre>([\s\S]*?)<\/pre>/i);
  if (preMatch) text = preMatch[1]!;
  text = text
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
  text = text.replace(/[\u200B\u200C\u200D\uFEFF]/g, "");
  return text;
}
