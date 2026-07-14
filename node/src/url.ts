import crypto from "node:crypto";
import { isIP } from "node:net";
import tls from "node:tls";

const SECRET_VM_PORT = 29343;
const SECRET_VM_RESOURCE_PATHS = new Set(["cpu", "gpu", "docker-compose"]);

export type ParsedEndpointUrl = {
  host: string;
  port: number;
  protocol: string;
  username: string;
  password: string;
  pathPrefix: string;
  search: string;
  hash: string;
};

export function normalizeConnectionHost(host: string): string {
  if (host.startsWith("[") && host.endsWith("]")) {
    return host.slice(1, -1);
  }
  return host;
}

export function formatUrlHost(host: string): string {
  const normalized = normalizeConnectionHost(host);
  return isIP(normalized) === 6 ? `[${normalized}]` : normalized;
}

export function normalizeEndpointUrl(url: string): string {
  url = url.trim();
  if (!url.includes("://")) url = `https://${url}`;
  return url;
}

function explicitAuthorityPort(normalizedUrl: string): number | undefined {
  const withoutScheme = normalizedUrl.replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "");
  const authority = withoutScheme.split(/[/?#]/, 1)[0] ?? "";
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close < 0) return undefined;
    const rest = authority.slice(close + 1);
    if (/^:\d+$/.test(rest)) return Number(rest.slice(1));
    return undefined;
  }
  const firstColon = authority.indexOf(":");
  const lastColon = authority.lastIndexOf(":");
  if (firstColon >= 0 && firstColon === lastColon) {
    const portText = authority.slice(lastColon + 1);
    if (/^\d+$/.test(portText)) return Number(portText);
  }
  return undefined;
}

// hasExplicitPort reports whether the URL's authority carries an explicit
// ":port". Used to decide whether default-port probing (29343 → 21434) applies:
// an explicit port is always honored as-is.
export function hasExplicitPort(url: string): boolean {
  return explicitAuthorityPort(normalizeEndpointUrl(url)) !== undefined;
}

function endpointPathPrefix(parsed: URL): string {
  const trimmed = parsed.pathname.replace(/\/+$/, "");
  return trimmed === "/" ? "" : trimmed;
}

export function parseEndpointUrl(url: string, defaultPort: number): ParsedEndpointUrl {
  const normalizedUrl = normalizeEndpointUrl(url);
  const explicitPort = explicitAuthorityPort(normalizedUrl);
  if (explicitPort !== undefined && (explicitPort < 1 || explicitPort > 65535)) {
    throw new Error("Endpoint URL has an invalid port");
  }
  const parsed = new URL(normalizedUrl);
  const host = normalizeConnectionHost(parsed.hostname);
  const port = explicitPort ?? (parsed.port ? Number(parsed.port) : defaultPort);
  if (port < 1 || port > 65535) {
    throw new Error("Endpoint URL has an invalid port");
  }
  return {
    host,
    port,
    protocol: parsed.protocol,
    username: parsed.username,
    password: parsed.password,
    pathPrefix: endpointPathPrefix(parsed),
    search: parsed.search,
    hash: parsed.hash,
  };
}

export function parseServiceBaseUrl(
  url: string,
  defaultPort: number,
  label = "SecretVM endpoint URL",
): ParsedEndpointUrl {
  const endpoint = parseEndpointUrl(url, defaultPort);
  if (endpoint.protocol !== "https:") {
    throw new Error(`${label} must use https://`);
  }
  if (endpoint.username !== "" || endpoint.password !== "") {
    throw new Error(`${label} must not include userinfo`);
  }
  if (endpoint.search !== "") {
    throw new Error(`${label} must not include a query string`);
  }
  if (endpoint.hash !== "") {
    throw new Error(`${label} must not include a fragment`);
  }
  const decodedSegments = endpoint.pathPrefix.split("/").filter(Boolean).map((segment) => {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw new Error(`${label} contains invalid percent-encoding`);
    }
    if (decoded.includes("/") || decoded.includes("\\")) {
      throw new Error(`${label} must not contain encoded path separators`);
    }
    return decoded;
  });
  const lastSegment = decodedSegments.at(-1);
  if (lastSegment !== undefined && SECRET_VM_RESOURCE_PATHS.has(lastSegment)) {
    throw new Error(
      `${label} must be a service base URL, not a concrete /${lastSegment} resource path`,
    );
  }
  return endpoint;
}

export function endpointBaseUrl(endpoint: ParsedEndpointUrl): string {
  return `https://${formatUrlHost(endpoint.host)}:${endpoint.port}${endpoint.pathPrefix}`;
}

export function tlsCertSpkiSha256(cert: crypto.X509Certificate): Buffer {
  const spki = cert.publicKey.export({ format: "der", type: "spki" });
  return crypto.createHash("sha256").update(spki).digest();
}

// tlsCertSha256 hashes the full DER certificate (the legacy binding, kept for
// backward-compatible verification of pre-SPKI VMs).
export function tlsCertSha256(cert: crypto.X509Certificate): Buffer {
  return crypto.createHash("sha256").update(cert.raw).digest();
}

// TlsCertBinding carries both digests report_data[0:32] may be bound to.
export type TlsCertBinding = { spki: Buffer; certificate: Buffer };

// classifyTlsBinding reports whether report_data's first 32 bytes match either the
// SPKI digest (current) or the legacy full-certificate digest, and which one.
export function classifyTlsBinding(
  reportDataFirstHalfHex: string,
  binding: TlsCertBinding,
): { verified: boolean; kind?: "spki" | "certificate" } {
  if (reportDataFirstHalfHex === binding.spki.toString("hex")) {
    return { verified: true, kind: "spki" };
  }
  if (reportDataFirstHalfHex === binding.certificate.toString("hex")) {
    return { verified: true, kind: "certificate" };
  }
  return { verified: false };
}

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
  const base = endpointBaseUrl(parseServiceBaseUrl(url, SECRET_VM_PORT));
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
 * Fetch the exact docker-compose bytes from a VM.
 */
export async function fetchDockerCompose(url: string): Promise<string> {
  return fetchVmEndpoint(url, "docker-compose");
}

// getTlsCertBinding connects once and returns both the SPKI and full-certificate
// SHA-256 digests, so report_data can be checked against either (SPKI for current
// VMs, full certificate for pre-SPKI VMs). rejectUnauthorized enforces the platform
// trust store before we hash anything.
export function getTlsCertBinding(
  host: string,
  port: number,
  servername = host,
): Promise<TlsCertBinding> {
  return new Promise((resolve, reject) => {
    host = normalizeConnectionHost(host);
    servername = normalizeConnectionHost(servername);
    const options: tls.ConnectionOptions = { host, port, rejectUnauthorized: true };
    if (servername && !isIP(servername)) {
      options.servername = servername;
    }

    const socket = tls.connect(
      options,
      () => {
        const cert = socket.getPeerX509Certificate();
        if (!cert) {
          socket.destroy();
          return reject(new Error("No certificate received"));
        }
        const binding: TlsCertBinding = {
          spki: tlsCertSpkiSha256(cert),
          certificate: tlsCertSha256(cert),
        };
        socket.destroy();
        resolve(binding);
      },
    );
    socket.on("error", reject);
    socket.setTimeout(10_000, () => {
      socket.destroy();
      reject(new Error("TLS connection timed out"));
    });
  });
}

// getTlsCertFingerprint returns just the SPKI digest, kept for backward compatibility
// with external callers of the previous API.
export async function getTlsCertFingerprint(
  host: string,
  port: number,
  servername = host,
): Promise<Buffer> {
  return (await getTlsCertBinding(host, port, servername)).spki;
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
