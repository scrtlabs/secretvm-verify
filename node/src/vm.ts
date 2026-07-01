import { AttestationResult, makeResult, orderChecks } from "./types.js";
import { checkCpuAttestation as checkCpuAttestationDefault } from "./cpu.js";
import { checkNvidiaGpuAttestation as checkNvidiaGpuAttestationDefault } from "./nvidia.js";
import { checkProofOfCloud as checkProofOfCloud_ } from "./proofOfCloud.js";
import { verifyWorkload as verifyWorkloadDefault, type DockerFilesInput } from "./workload.js";
import {
  endpointBaseUrl,
  extractDockerCompose,
  getTlsCertFingerprint as getTlsCertFingerprintDefault,
  normalizeEndpointUrl,
  parseEndpointUrl,
  parseServiceBaseUrl,
} from "./url.js";

const SECRET_VM_PORT = 29343;
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
};

export type SecretVmRuntime = {
  fetch: typeof fetch;
  getTlsCertFingerprint: typeof getTlsCertFingerprintDefault;
  checkCpuAttestation: typeof checkCpuAttestationDefault;
  checkNvidiaGpuAttestation: typeof checkNvidiaGpuAttestationDefault;
  verifyWorkload: typeof verifyWorkloadDefault;
};

function defaultSecretVmRuntime(): SecretVmRuntime {
  return {
    fetch: globalThis.fetch,
    getTlsCertFingerprint: getTlsCertFingerprintDefault,
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

function makeAttestationEndpoint(url: string): SecretVmEndpoint {
  const parsed = parseServiceBaseUrl(url, SECRET_VM_PORT, "Attestation URL");
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
): Promise<AttestationResult>;
export async function checkSecretVm(
  url: string,
  productOrOptions: string | CheckSecretVmOptions = "",
  reloadAmdKds = false,
  checkProofOfCloud = false,
  dockerFilesInput?: DockerFilesInput,
  strict = false,
  tlsUrl?: string,
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

  let endpoints: ReturnType<typeof resolveSecretVmEndpoints>;
  try {
    endpoints = resolveSecretVmEndpoints(url, options.tlsUrl);
  } catch (e: any) {
    return makeResult("SECRET-VM", { errors: [e.message] });
  }

  const baseUrl = endpoints.attestation.baseUrl;
  report.attestation_url = endpoints.attestation.baseUrl;
  report.tls_binding_url = endpoints.tls.baseUrl;

  // 1. TLS certificate SPKI fingerprint
  let tlsSpkiFingerprint: Buffer;
  try {
    tlsSpkiFingerprint = await runtime.getTlsCertFingerprint(
      endpoints.tls.host,
      endpoints.tls.port,
      endpoints.tls.servername,
    );
    checks.tls_cert_fetched = true;
    report.tls_spki_fingerprint = tlsSpkiFingerprint.toString("hex");
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

  // 3. TLS binding: first 32 bytes of report_data == SHA-256(TLS SPKI DER)
  const reportDataHex: string = cpuResult.report.report_data ?? "";
  if (reportDataHex.length >= 64) {
    const firstHalf = reportDataHex.slice(0, 64);
    checks.tls_binding_verified = firstHalf === tlsSpkiFingerprint.toString("hex");
    if (!checks.tls_binding_verified) {
      errors.push(
        `TLS binding failed: report_data first half (${firstHalf.slice(0, 16)}...) ` +
          `!= TLS SPKI fingerprint (${tlsSpkiFingerprint.toString("hex").slice(0, 16)}...)`,
      );
    }
  } else {
    checks.tls_binding_verified = false;
    errors.push("report_data too short for TLS binding check");
  }

  // 4. Fetch and verify GPU quote
  let gpuData = "";
  let gpuJson: Record<string, any> | undefined;
  try {
    const resp = await runtime.fetch(`${baseUrl}/gpu`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    gpuData = await resp.text();
    const parsedGpu = JSON.parse(gpuData) as Record<string, any>;
    if ("error" in parsedGpu) {
      throw new Error(String(parsedGpu.error));
    }
    if (typeof parsedGpu.nonce !== "string" || parsedGpu.nonce === "") {
      throw new Error("GPU attestation missing nonce");
    }
    gpuJson = parsedGpu;
    checks.gpu_quote_fetched = true;
  } catch (e: any) {
    checks.gpu_quote_fetched = false;
    checks.gpu_quote_verified = false;
    checks.gpu_binding_verified = false;
    errors.push(`Failed to fetch GPU attestation: ${e.message}`);
  }

  if (checks.gpu_quote_fetched) {
    const gpuResult = await runtime.checkNvidiaGpuAttestation(gpuData);
    checks.gpu_quote_verified = gpuResult.valid;
    report.gpu = gpuResult.report;
    if (!gpuResult.valid) {
      errors.push(...gpuResult.errors);
    }

    // 5. GPU binding: second 32 bytes of report_data == GPU nonce
    const gpuNonce: string = gpuJson!.nonce;
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

  // 6. Fetch and verify workload (docker-compose)
  try {
    const resp = await runtime.fetch(`${baseUrl}/docker-compose`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const dockerCompose = await resp.text();
    checks.workload_fetched = true;

    const workloadResult = await runtime.verifyWorkload(cpuData, dockerCompose, dockerFilesInput);
    checks.workload_binding_verified = workloadResult.status === "authentic_match";
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
    checks.gpu_quote_fetched,
    checks.gpu_quote_verified,
    checks.gpu_binding_verified,
    !!checks.workload_binding_verified,
  ];
  if (checkProofOfCloud) {
    requiredChecks.push(!!checks.proof_of_cloud_verified);
  }
  const valid = requiredChecks.every(Boolean);

  return makeResult("SECRET-VM", { valid, checks: orderChecks(checks), report, errors });
}
