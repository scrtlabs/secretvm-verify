import { ethers } from "ethers";
import { getChainConfig, getRpcUrl } from "./chains.js";
import { AttestationResult, makeResult, orderChecks } from "./types.js";
import type { AgentMetadata, AgentService } from "./types.js";
import { checkCpuAttestation } from "./cpu.js";
import { checkNvidiaGpuAttestation } from "./nvidia.js";
import { checkProofOfCloud as checkProofOfCloud_ } from "./proofOfCloud.js";
import { verifyWorkload } from "./workload.js";
import { endpointBaseUrl, getTlsCertFingerprint, parseServiceBaseUrl } from "./url.js";
import { resolveSecretVmEndpoints, type SecretVmEndpoint } from "./vm.js";

const SECRET_VM_PORT = 29343;

const REGISTRY_ABI = [
  "function tokenURI(uint256 tokenId) view returns (string)",
  "function agentURI(uint256 agentId) view returns (string)",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function normalizeServices(raw: unknown): AgentService[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((service, index) => {
    const entry = (service ?? {}) as Record<string, unknown>;
    const name = typeof entry.name === "string" ? entry.name : "";
    const endpoint = typeof entry.endpoint === "string" ? entry.endpoint : "";
    const description = typeof entry.description === "string" ? entry.description : "";
    return {
      name: name || `service-${index + 1}`,
      endpoint,
      description,
    };
  });
}

function findRequiredUniqueService(
  services: AgentService[],
  serviceName: string,
): { endpoint?: string; error?: string } {
  const matches = services.filter(
    (s) => s.name.toLowerCase() === serviceName && s.endpoint.trim() !== "",
  );
  if (matches.length === 0) {
    return { error: `No ${serviceName} service endpoint found in agent metadata` };
  }
  if (matches.length > 1) {
    return { error: `Multiple ${serviceName} service endpoints found in agent metadata` };
  }
  return { endpoint: matches[0]!.endpoint.trim() };
}

function findOptionalUniqueService(
  services: AgentService[],
  serviceName: string,
): { endpoint?: string; error?: string } {
  const matches = services.filter(
    (s) => s.name.toLowerCase() === serviceName && s.endpoint.trim() !== "",
  );
  if (matches.length > 1) {
    return { error: `Multiple ${serviceName} service endpoints found in agent metadata` };
  }
  return { endpoint: matches[0]?.endpoint.trim() };
}

function endpointIdentity(endpoint: SecretVmEndpoint): string {
  return `${endpoint.host.toLowerCase()}:${endpoint.port}`;
}

export function resolveAgentSecretVmEndpoints(
  services: AgentService[],
): {
  endpoints?: ReturnType<typeof resolveSecretVmEndpoints>;
  tlsBindingServiceName?: string;
  error?: string;
} {
  const teequote = findRequiredUniqueService(services, "teequote");
  if (teequote.error || !teequote.endpoint) {
    return { error: teequote.error };
  }

  const inference = findRequiredUniqueService(services, "inference");
  if (inference.error || !inference.endpoint) {
    return { error: inference.error };
  }

  let endpoints: ReturnType<typeof resolveSecretVmEndpoints>;
  try {
    endpoints = resolveSecretVmEndpoints(teequote.endpoint, inference.endpoint);
  } catch (e: any) {
    return { error: e.message };
  }

  return { endpoints, tlsBindingServiceName: "inference" };
}

function normalizeEndpoint(endpoint: string): string {
  if (!endpoint.startsWith("http://") && !endpoint.startsWith("https://")) {
    return `https://${endpoint}`;
  }
  return endpoint;
}

// ---------------------------------------------------------------------------
// Public: resolveAgent
// ---------------------------------------------------------------------------

/**
 * Resolve an ERC-8004 agent's metadata from the on-chain registry.
 *
 * Queries the registry contract for the agent's tokenURI, fetches the
 * metadata JSON, and returns a normalized AgentMetadata object.
 *
 * RPC URL resolution priority:
 *   1. SECRETVM_RPC_<CHAIN> env var (e.g. SECRETVM_RPC_BASE)
 *   2. SECRETVM_RPC_URL env var (generic fallback)
 *
 * Throws if no RPC URL is configured.
 */
export async function resolveAgent(
  agentId: number,
  chain: string,
): Promise<AgentMetadata> {
  const chainConfig = getChainConfig(chain);
  const rpcUrl = getRpcUrl(chain);
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const contract = new ethers.Contract(
    chainConfig.registryAddress,
    REGISTRY_ABI,
    provider,
  );

  let tokenUri: string;
  try {
    tokenUri = await contract.tokenURI(agentId);
  } catch {
    try {
      tokenUri = await contract.agentURI(agentId);
    } catch {
      throw new Error(
        `Could not find tokenURI or agentURI for agent ${agentId} on ${chainConfig.name}`,
      );
    }
  }

  if (!tokenUri || tokenUri.trim() === "") {
    throw new Error(`Registry returned empty tokenURI for agent ${agentId}`);
  }

  let manifest: Record<string, unknown>;
  if (tokenUri.startsWith("data:")) {
    // Handle data URIs (e.g. data:application/json;base64,...)
    const encoded = tokenUri.split(",", 2)[1]!;
    manifest = JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
  } else {
    let fetchUrl = tokenUri;
    if (fetchUrl.startsWith("ipfs://")) {
      fetchUrl = fetchUrl.replace("ipfs://", "https://ipfs.io/ipfs/");
    }
    const resp = await fetch(fetchUrl);
    if (!resp.ok) {
      throw new Error(`Failed to fetch agent metadata from ${fetchUrl}: HTTP ${resp.status}`);
    }
    manifest = (await resp.json()) as Record<string, unknown>;
  }

  const trust =
    (manifest.supportedTrust as string[] | undefined) ??
    (manifest.supported_trust as string[] | undefined) ??
    [];

  return {
    name:
      typeof manifest.name === "string" && manifest.name.trim()
        ? manifest.name
        : `Agent ${agentId}`,
    description:
      typeof manifest.description === "string" ? manifest.description : undefined,
    supportedTrust: Array.isArray(trust) ? trust : [],
    services: normalizeServices(manifest.services ?? manifest.endpoints),
    image: typeof manifest.image === "string" ? manifest.image : undefined,
    type: typeof manifest.type === "string" ? manifest.type : undefined,
    active: manifest.active !== undefined ? Boolean(manifest.active) : true,
    x402Support: Boolean(manifest.x402Support ?? false),
    attributes: (manifest.attributes as Record<string, any>) ?? {},
    raw: manifest,
  };
}

// ---------------------------------------------------------------------------
// Public: verifyAgent
// ---------------------------------------------------------------------------

/**
 * Verify an ERC-8004 agent given its metadata.
 *
 * Discovers teequote and workload endpoints from the metadata, then runs
 * the full verification flow: TLS cert, CPU quote, TLS binding, GPU quote,
 * GPU binding, and workload verification.
 *
 * @param reloadAmdKds If true, bypass the local AMD KDS cache and re-fetch
 *   VCEK / cert chain / CRL. No effect on TDX agents.
 */
export async function verifyAgent(
  metadata: AgentMetadata,
  reloadAmdKds = false,
  checkProofOfCloud = false,
  strict = false,
): Promise<AttestationResult> {
  const errors: string[] = [];
  const checks: Record<string, boolean> = {};
  const report: Record<string, any> = {};

  report.agent_name = metadata.name;

  // 1. Validate metadata
  const hasTeeAttestation = metadata.supportedTrust
    .map((t) => t.toLowerCase())
    .includes("tee-attestation");
  if (!hasTeeAttestation) {
    errors.push("Agent does not support tee-attestation");
    checks.metadata_valid = false;
    return makeResult("ERC-8004", { checks: orderChecks(checks), report, errors });
  }

  const services = normalizeServices(metadata.services);
  const agentEndpoints = resolveAgentSecretVmEndpoints(services);
  if (!agentEndpoints.endpoints) {
    errors.push(agentEndpoints.error ?? "Could not resolve agent SecretVM endpoints");
    checks.metadata_valid = false;
    return makeResult("ERC-8004", { checks: orderChecks(checks), report, errors });
  }
  const workloadService = findOptionalUniqueService(services, "workload");
  if (workloadService.error) {
    errors.push(workloadService.error);
    checks.metadata_valid = false;
    return makeResult("ERC-8004", { checks: orderChecks(checks), report, errors });
  }
  let workloadBaseUrl: string | undefined;
  if (workloadService.endpoint) {
    try {
      workloadBaseUrl = endpointBaseUrl(
        parseServiceBaseUrl(workloadService.endpoint, SECRET_VM_PORT, "workload service endpoint"),
      );
    } catch (e: any) {
      errors.push(e.message);
      checks.metadata_valid = false;
      return makeResult("ERC-8004", { checks: orderChecks(checks), report, errors });
    }
  }
  checks.metadata_valid = true;

  // 2. Derive URLs
  const endpoints = agentEndpoints.endpoints;
  const baseUrl = endpoints.attestation.baseUrl;
  const cpuUrl = `${baseUrl}/cpu`;
  const gpuUrl = `${baseUrl}/gpu`;

  const workloadUrl = `${workloadBaseUrl ?? baseUrl}/docker-compose`;

  report.attestation_url = endpoints.attestation.baseUrl;
  report.tls_binding_url = endpoints.tls.baseUrl;
  report.tls_binding_service = agentEndpoints.tlsBindingServiceName;

  // 3. TLS certificate SPKI fingerprint
  let tlsSpkiFingerprint: Buffer;
  try {
    tlsSpkiFingerprint = await getTlsCertFingerprint(
      endpoints.tls.host,
      endpoints.tls.port,
      endpoints.tls.servername,
    );
    checks.tls_cert_fetched = true;
    report.tls_spki_fingerprint = tlsSpkiFingerprint.toString("hex");
  } catch (e: any) {
    errors.push(`Failed to get TLS certificate: ${e.message}`);
    checks.tls_cert_fetched = false;
    return makeResult("ERC-8004", { checks: orderChecks(checks), report, errors });
  }

  // 4. Fetch and verify CPU quote
  let cpuData: string;
  try {
    const resp = await fetch(cpuUrl);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    cpuData = await resp.text();
    checks.cpu_quote_fetched = true;
  } catch (e: any) {
    errors.push(`Failed to fetch CPU quote: ${e.message}`);
    checks.cpu_quote_fetched = false;
    return makeResult("ERC-8004", { checks: orderChecks(checks), report, errors });
  }

  const cpuResult = await checkCpuAttestation(cpuData, "", reloadAmdKds, strict);
  checks.cpu_quote_verified = cpuResult.valid;
  report.cpu = cpuResult.report;
  report.cpu_type = cpuResult.attestationType;
  if (!cpuResult.valid) errors.push(...cpuResult.errors);

  // 5. TLS binding: first 32 bytes of report_data == SHA-256(TLS SPKI DER)
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

  // 6. GPU quote
  let gpuData = "";
  let gpuJson: Record<string, any> | undefined;
  try {
    const resp = await fetch(gpuUrl);
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
    const gpuResult = await checkNvidiaGpuAttestation(gpuData);
    checks.gpu_quote_verified = gpuResult.valid;
    report.gpu = gpuResult.report;
    if (!gpuResult.valid) errors.push(...gpuResult.errors);

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

  // 7. Workload verification
  try {
    const resp = await fetch(workloadUrl);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const dockerCompose = await resp.text();
    checks.workload_fetched = true;

    const workloadResult = await verifyWorkload(cpuData, dockerCompose);
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

  // 8. Proof of cloud (opt-in): confirm the quote was produced on a Secret VM.
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
    checks.metadata_valid,
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

  return makeResult("ERC-8004", { valid, checks: orderChecks(checks), report, errors });
}

// ---------------------------------------------------------------------------
// Public: checkAgent
// ---------------------------------------------------------------------------

/**
 * End-to-end ERC-8004 agent verification.
 *
 * Resolves the agent's metadata from the on-chain registry, then runs
 * the full verification flow via verifyAgent.
 *
 * @param reloadAmdKds If true, bypass the local AMD KDS cache and re-fetch
 *   VCEK / cert chain / CRL. No effect on TDX agents.
 */
export async function checkAgent(
  agentId: number,
  chain: string,
  reloadAmdKds = false,
  checkProofOfCloud = false,
  strict = false,
): Promise<AttestationResult> {
  const errors: string[] = [];
  const checks: Record<string, boolean> = {};

  let metadata: AgentMetadata;
  try {
    metadata = await resolveAgent(agentId, chain);
    checks.agent_resolved = true;
  } catch (e: any) {
    errors.push(`Failed to resolve agent: ${e.message}`);
    checks.agent_resolved = false;
    return makeResult("ERC-8004", { checks: orderChecks(checks), errors });
  }

  const result = await verifyAgent(metadata, reloadAmdKds, checkProofOfCloud, strict);
  result.checks = { agent_resolved: true, ...result.checks };

  return result;
}
