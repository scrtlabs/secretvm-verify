import { AttestationResult, makeResult, orderChecks } from "./types.js";
import { checkCpuAttestation as checkCpuAttestationDefault } from "./cpu.js";
import { checkNvidiaGpuAttestation as checkNvidiaGpuAttestationDefault } from "./nvidia.js";
import { checkProofOfCloud as checkProofOfCloud_ } from "./proofOfCloud.js";
import { verifyWorkload as verifyWorkloadDefault, extractDstackAppId, type DockerFilesInput } from "./workload.js";
import {
  classifyTlsBinding,
  endpointBaseUrl,
  extractDockerCompose,
  getTlsCertBinding as getTlsCertBindingDefault,
  hasExplicitPort,
  normalizeEndpointUrl,
  parseEndpointUrl,
  parseServiceBaseUrl,
} from "./url.js";

const SECRET_VM_PORT = 29343;
// When a bare host (no explicit port) is given, we probe SECRET_VM_PORT first
// (attest-rest bound directly, standard VMs) and fall back to this port, where
// a host-net Caddy fronts the app-cert TLS and proxies the evidence endpoints
// (jedi/rytn topology; attest-rest is loopback-only and unreachable on 29343).
const SECRET_VM_TLS_FALLBACK_PORT = 21434;
const PROBE_TIMEOUT_MS = 5000;
const HTTPS_PORT = 443;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Re-export for backwards compatibility
export { extractDockerCompose };

export type SecretVmEndpoint = {
  host: string;
  port: number;
  servername: string;
  pathPrefix: string;
  baseUrl: string;
};

export type CheckSecretVmOptions = {
  product?: string;
  reloadAmdKds?: boolean;
  checkProofOfCloud?: boolean;
  dockerFilesInput?: DockerFilesInput;
  strict?: boolean;
  tlsUrl?: string;
  enforceGpu?: boolean;
};

export type SecretVmRuntime = {
  fetch: typeof fetch;
  getTlsCertBinding: typeof getTlsCertBindingDefault;
  checkCpuAttestation: typeof checkCpuAttestationDefault;
  checkNvidiaGpuAttestation: typeof checkNvidiaGpuAttestationDefault;
  verifyWorkload: typeof verifyWorkloadDefault;
};

function defaultSecretVmRuntime(): SecretVmRuntime {
  return {
    fetch: globalThis.fetch,
    getTlsCertBinding: getTlsCertBindingDefault,
    checkCpuAttestation: checkCpuAttestationDefault,
    checkNvidiaGpuAttestation: checkNvidiaGpuAttestationDefault,
    verifyWorkload: verifyWorkloadDefault,
  };
}

function isExplicitUrl(value: string): boolean {
  const trimmed = value.trim();
  return /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(trimmed);
}

export function isEndpointLike(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === "") return false;
  if (isExplicitUrl(trimmed)) return true;
  if (trimmed.startsWith("[") || trimmed.includes(":") || trimmed.includes("/")) {
    return true;
  }
  if (trimmed === "localhost") return true;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed)) return true;
  return /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(trimmed);
}

export function parseVmUrl(url: string): { host: string; port: number } {
  const parsed = parseEndpointUrl(url, SECRET_VM_PORT);
  return {
    host: parsed.host,
    port: parsed.port,
  };
}

function makeAttestationEndpoint(
  url: string,
  defaultPort: number = SECRET_VM_PORT,
): SecretVmEndpoint {
  const parsed = parseServiceBaseUrl(url, defaultPort, "Attestation URL");
  return {
    host: parsed.host,
    port: parsed.port,
    servername: parsed.host,
    pathPrefix: parsed.pathPrefix,
    baseUrl: endpointBaseUrl(parsed),
  };
}

function makeTlsEndpoint(url: string): SecretVmEndpoint {
  url = url.trim();
  if (url === "") {
    throw new Error("TLS binding URL must not be empty");
  }
  const normalizedUrl = normalizeEndpointUrl(url);
  const parsed = new URL(normalizedUrl);
  if (parsed.protocol !== "https:") {
    throw new Error("TLS binding URL must use https://");
  }
  const { host, port, username, password, pathPrefix, search, hash } = parseEndpointUrl(url, HTTPS_PORT);
  if (username !== "" || password !== "") {
    throw new Error("TLS binding URL must not include userinfo");
  }
  if (pathPrefix !== "") {
    throw new Error("TLS binding URL must not include a path");
  }
  if (search !== "") {
    throw new Error("TLS binding URL must not include a query string");
  }
  if (hash !== "") {
    throw new Error("TLS binding URL must not include a fragment");
  }
  return {
    host,
    port,
    servername: host,
    pathPrefix: "",
    baseUrl: endpointBaseUrl({
      host,
      port,
      protocol: "https:",
      username: "",
      password: "",
      pathPrefix: "",
      search: "",
      hash: "",
    }),
  };
}

export function resolveSecretVmEndpoints(
  attestationUrl: string,
  tlsUrl?: string,
): { attestation: SecretVmEndpoint; tls: SecretVmEndpoint } {
  const attestation = makeAttestationEndpoint(attestationUrl);
  return {
    attestation,
    tls: tlsUrl === undefined ? attestation : makeTlsEndpoint(tlsUrl),
  };
}

// probeCpu returns true if the endpoint answers GET /cpu within the timeout.
// A reachable /cpu marks the origin that serves both the quote and the
// app-cert TLS, so attestation and tls endpoints share that port.
async function probeCpu(
  endpoint: SecretVmEndpoint,
  fetchImpl: typeof fetch,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS);
  try {
    const resp = await fetchImpl(`${endpoint.baseUrl}/cpu`, { signal: controller.signal });
    return resp.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

// resolveSecretVmEndpointsWithFallback mirrors resolveSecretVmEndpoints but,
// when the URL carries no explicit port and no separate tls URL was given,
// probes SECRET_VM_PORT (29343) then SECRET_VM_TLS_FALLBACK_PORT (21434) and
// binds both endpoints to whichever answers /cpu. An explicit port or an
// explicit tls URL disables probing and preserves the exact prior behavior.
async function resolveSecretVmEndpointsWithFallback(
  attestationUrl: string,
  tlsUrl: string | undefined,
  fetchImpl: typeof fetch,
): Promise<{ attestation: SecretVmEndpoint; tls: SecretVmEndpoint }> {
  if (tlsUrl !== undefined || hasExplicitPort(attestationUrl)) {
    return resolveSecretVmEndpoints(attestationUrl, tlsUrl);
  }
  const candidatePorts = [SECRET_VM_PORT, SECRET_VM_TLS_FALLBACK_PORT];
  let first: SecretVmEndpoint | undefined;
  for (const port of candidatePorts) {
    const endpoint = makeAttestationEndpoint(attestationUrl, port);
    if (first === undefined) first = endpoint;
    if (await probeCpu(endpoint, fetchImpl)) {
      return { attestation: endpoint, tls: endpoint };
    }
  }
  // None reachable: fall back to the primary port so downstream fetch surfaces
  // a clear error against 29343.
  return { attestation: first!, tls: first! };
}

// ---------------------------------------------------------------------------
// Public
// ---------------------------------------------------------------------------

export async function checkSecretVm(
  url: string,
  options?: CheckSecretVmOptions,
): Promise<AttestationResult>;
export async function checkSecretVm(
  url: string,
  product?: string,
  reloadAmdKds?: boolean,
  checkProofOfCloud?: boolean,
  dockerFilesInput?: DockerFilesInput,
  strict?: boolean,
  tlsUrl?: string,
  enforceGpu?: boolean,
): Promise<AttestationResult>;
export async function checkSecretVm(
  url: string,
  productOrOptions: string | CheckSecretVmOptions = "",
  reloadAmdKds = false,
  checkProofOfCloud = false,
  dockerFilesInput?: DockerFilesInput,
  strict = false,
  tlsUrl?: string,
  enforceGpu = false,
): Promise<AttestationResult> {
  let options: CheckSecretVmOptions;

  if (typeof productOrOptions === "object") {
    options = productOrOptions;
  } else {
    if (productOrOptions !== "" && isEndpointLike(productOrOptions)) {
      return makeResult("SECRET-VM", {
        errors: [
          `Endpoint-like second argument ${JSON.stringify(productOrOptions)} is not a product name. ` +
            "Pass split service endpoints with checkSecretVm(url, { tlsUrl: ... }).",
        ],
      });
    }
    options = {
      product: productOrOptions,
      reloadAmdKds,
      checkProofOfCloud,
      dockerFilesInput,
      strict,
      tlsUrl,
      enforceGpu,
    };
  }

  return checkSecretVmWithRuntime(url, options, defaultSecretVmRuntime());
}

export async function checkSecretVmWithRuntime(
  url: string,
  options: CheckSecretVmOptions,
  runtime: SecretVmRuntime,
): Promise<AttestationResult> {
  const errors: string[] = [];
  const checks: Record<string, boolean> = {};
  const report: Record<string, any> = {};
  const product = options.product ?? "";
  const reloadAmdKds = options.reloadAmdKds ?? false;
  const checkProofOfCloud = options.checkProofOfCloud ?? false;
  const dockerFilesInput = options.dockerFilesInput;
  const strict = options.strict ?? false;
  const enforceGpu = options.enforceGpu ?? false;

  let endpoints: ReturnType<typeof resolveSecretVmEndpoints>;
  try {
    endpoints = await resolveSecretVmEndpointsWithFallback(url, options.tlsUrl, runtime.fetch);
  } catch (e: any) {
    return makeResult("SECRET-VM", { errors: [e.message] });
  }

  const baseUrl = endpoints.attestation.baseUrl;
  report.attestation_url = endpoints.attestation.baseUrl;
  report.tls_binding_url = endpoints.tls.baseUrl;

  // 1. TLS certificate digests (SPKI + full certificate, for backward compat)
  let tlsBinding: Awaited<ReturnType<typeof getTlsCertBindingDefault>>;
  try {
    tlsBinding = await runtime.getTlsCertBinding(
      endpoints.tls.host,
      endpoints.tls.port,
      endpoints.tls.servername,
    );
    checks.tls_cert_fetched = true;
    report.tls_spki_fingerprint = tlsBinding.spki.toString("hex");
    report.tls_certificate_fingerprint = tlsBinding.certificate.toString("hex");
  } catch (e: any) {
    errors.push(`Failed to get TLS certificate: ${e.message}`);
    checks.tls_cert_fetched = false;
    return makeResult("SECRET-VM", { checks: orderChecks(checks), report, errors });
  }

  // 2. Fetch and verify CPU quote
  let cpuData: string;
  try {
    const resp = await runtime.fetch(`${baseUrl}/cpu`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    cpuData = await resp.text();
    checks.cpu_quote_fetched = true;
  } catch (e: any) {
    errors.push(`Failed to fetch CPU quote: ${e.message}`);
    checks.cpu_quote_fetched = false;
    return makeResult("SECRET-VM", { checks: orderChecks(checks), report, errors });
  }

  const cpuResult = await runtime.checkCpuAttestation(cpuData, product, reloadAmdKds, strict);
  checks.cpu_quote_verified = cpuResult.valid;
  report.cpu = cpuResult.report;
  report.cpu_type = cpuResult.attestationType;
  if (!cpuResult.valid) {
    errors.push(...cpuResult.errors);
  }

  // 3. TLS binding: first 32 bytes of report_data == SHA-256(SPKI DER) [current]
  //    or SHA-256(full certificate DER) [legacy]. Accept either so a mixed fleet
  //    (SPKI-pinned + older full-cert VMs) keeps verifying.
  const reportDataHex: string = cpuResult.report.report_data ?? "";
  if (reportDataHex.length >= 64) {
    const firstHalf = reportDataHex.slice(0, 64);
    const binding = classifyTlsBinding(firstHalf, tlsBinding);
    checks.tls_binding_verified = binding.verified;
    if (binding.verified) {
      report.tls_binding_kind = binding.kind;
    } else {
      errors.push(
        `TLS binding failed: report_data first half (${firstHalf.slice(0, 16)}...) ` +
          `!= TLS SPKI (${tlsBinding.spki.toString("hex").slice(0, 16)}...) ` +
          `or certificate (${tlsBinding.certificate.toString("hex").slice(0, 16)}...) digest`,
      );
    }
  } else {
    checks.tls_binding_verified = false;
    errors.push("report_data too short for TLS binding check");
  }

  // 4. Fetch GPU quote (optional). GPU is only required when enforceGpu is set.
  let gpuPresent = false;
  let gpuData = "";
  try {
    const resp = await runtime.fetch(`${baseUrl}/gpu`);
    if (resp.ok) {
      gpuData = await resp.text();
      const parsed = JSON.parse(gpuData);
      if ("error" in parsed) {
        checks.gpu_quote_fetched = false;
      } else {
        gpuPresent = true;
        checks.gpu_quote_fetched = true;
      }
    } else {
      checks.gpu_quote_fetched = false;
    }
  } catch {
    checks.gpu_quote_fetched = false;
  }

  if (gpuPresent) {
    const gpuResult = await runtime.checkNvidiaGpuAttestation(gpuData);
    checks.gpu_quote_verified = gpuResult.valid;
    report.gpu = gpuResult.report;
    if (!gpuResult.valid) {
      errors.push(...gpuResult.errors);
    }

    // 5. GPU binding: second 32 bytes of report_data == GPU nonce
    const gpuJson = JSON.parse(gpuData);
    const gpuNonce: string = gpuJson.nonce ?? "";
    if (reportDataHex.length >= 128) {
      const secondHalf = reportDataHex.slice(64, 128);
      checks.gpu_binding_verified = secondHalf === gpuNonce;
      if (!checks.gpu_binding_verified) {
        errors.push(
          `GPU binding failed: report_data second half (${secondHalf.slice(0, 16)}...) ` +
            `!= GPU nonce (${gpuNonce.slice(0, 16)}...)`,
        );
      }
    } else {
      checks.gpu_binding_verified = false;
      errors.push("report_data too short for GPU binding check");
    }
  }

  // 5b. GPU enforcement (opt-in): when enforceGpu is set, a GPU must be present,
  // so a CPU-only VM fails closed instead of silently passing.
  if (enforceGpu) {
    checks.gpu_present = gpuPresent;
    if (!gpuPresent) {
      errors.push(
        "GPU attestation required (--enforce-gpu) but this VM exposes no GPU",
      );
    }
  }

  // 6. Fetch and verify workload (docker-compose)
  try {
    const resp = await runtime.fetch(`${baseUrl}/docker-compose`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const dockerCompose = await resp.text();
    checks.workload_fetched = true;

    // Newer (dstack) VMs measure the app-id as RTMR3's first event. Fetch it
    // from /info (best-effort — older images have no /info, so we fall back to
    // the pre-dstack schema and never fail the check on a missing endpoint).
    let dstackAppId = "";
    try {
      const infoResp = await runtime.fetch(`${baseUrl}/info`);
      if (infoResp.ok) dstackAppId = extractDstackAppId(await infoResp.text());
    } catch {
      /* no /info endpoint — old schema */
    }
    const workloadResult = await runtime.verifyWorkload(cpuData, dockerCompose, dockerFilesInput, dstackAppId);
    checks.workload_binding_verified = workloadResult.status === "authentic_match";
    // The app-id is only *proven* when it was an input to a TDX RTMR3 replay
    // that reproduced a hardware-signed quote. SEV-SNP has no app-id in its
    // launch measurement, and a failed TDX replay proves nothing either — in
    // both cases the value is whatever the VM chose to serve on /info. The
    // cpuResult.valid conjunct matters because verification does not stop at a
    // failed CPU quote: verifyTdxWorkload replays measurements without checking
    // the DCAP signature, so an unsigned quote carrying copied measurements can
    // still reach authentic_match. Report the value either way (it is useful
    // for diagnosis) but never without saying which case it is.
    if (dstackAppId) {
      report.dstack_app_id = dstackAppId;
      report.dstack_app_id_verified =
        cpuResult.valid &&
        report.cpu_type === "TDX" &&
        workloadResult.status === "authentic_match";
    }
    report.workload = workloadResult;
    report.docker_compose = dockerCompose;
    if (workloadResult.status === "authentic_mismatch") {
      errors.push("Workload mismatch: VM is authentic but docker-compose does not match");
    } else if (workloadResult.status === "not_authentic") {
      errors.push("Workload verification failed: not an authentic SecretVM");
    }
  } catch (e: any) {
    errors.push(`Failed to fetch workload: ${e.message}`);
    checks.workload_fetched = false;
  }

  // 7. Proof of cloud (opt-in): the community trust-server peers confirm the
  // machine is on the Proof of Cloud whitelist. Disabled by default — pass
  // checkProofOfCloud=true (or --proof-of-cloud on the CLI) to include this check.
  if (checkProofOfCloud) {
    const pocResult = await checkProofOfCloud_(cpuData);
    checks.proof_of_cloud_verified = pocResult.valid;
    if (pocResult.report.proof_of_cloud !== undefined) {
      report.proof_of_cloud = pocResult.report.proof_of_cloud;
    }
    if (!pocResult.valid) {
      errors.push(...pocResult.errors);
    }
  }

  // Overall validity
  const requiredChecks = [
    checks.tls_cert_fetched,
    checks.cpu_quote_fetched,
    checks.cpu_quote_verified,
    checks.tls_binding_verified,
    !!checks.workload_binding_verified,
  ];
  if (checkProofOfCloud) {
    requiredChecks.push(!!checks.proof_of_cloud_verified);
  }
  if (enforceGpu) {
    requiredChecks.push(!!checks.gpu_present);
  }
  if (gpuPresent) {
    requiredChecks.push(!!checks.gpu_quote_verified);
    requiredChecks.push(!!checks.gpu_binding_verified);
  }
  const valid = requiredChecks.every(Boolean);

  return makeResult("SECRET-VM", { valid, checks: orderChecks(checks), report, errors });
}
