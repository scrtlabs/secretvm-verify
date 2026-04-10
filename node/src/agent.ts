import { ethers } from "ethers";
import { getChainConfig, getRpcUrl } from "./chains.js";
import { AttestationResult, makeResult } from "./types.js";
import type { AgentMetadata, AgentService } from "./types.js";
import { checkCpuAttestation } from "./cpu.js";
import { checkNvidiaGpuAttestation } from "./nvidia.js";
import { verifyWorkload } from "./workload.js";
import { extractDockerCompose, getTlsCertFingerprint } from "./url.js";

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

function findTeequoteEndpoint(services: AgentService[]): string | undefined {
  for (const s of services) {
    if (s.name.toLowerCase() === "teequote" && s.endpoint) return s.endpoint;
  }
  for (const s of services) {
    if (s.endpoint && s.endpoint.includes(":29343")) return s.endpoint;
  }
  return undefined;
}

function findWorkloadEndpoint(services: AgentService[]): string | undefined {
  for (const s of services) {
    if (s.name.toLowerCase() === "workload" && s.endpoint) return s.endpoint;
  }
  return undefined;
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
 *   3. Default public RPC for the chain
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
    return makeResult("ERC-8004", { checks, report, errors });
  }

  const teequoteEndpoint = findTeequoteEndpoint(metadata.services);
  if (!teequoteEndpoint) {
    errors.push("No teequote service endpoint found in agent metadata");
    checks.metadata_valid = false;
    return makeResult("ERC-8004", { checks, report, errors });
  }
  checks.metadata_valid = true;

  // 2. Derive URLs
  const baseUrl = normalizeEndpoint(teequoteEndpoint).replace(/\/+$/, "");
  const cpuUrl = baseUrl.endsWith("/cpu") ? baseUrl : `${baseUrl}/cpu`;
  const gpuUrl = baseUrl.endsWith("/cpu")
    ? baseUrl.replace(/\/cpu$/, "/gpu")
    : `${baseUrl}/gpu`;

  const workloadService = findWorkloadEndpoint(metadata.services);
  const workloadUrl = workloadService
    ? normalizeEndpoint(workloadService)
    : baseUrl.endsWith("/cpu")
      ? baseUrl.replace(/\/cpu$/, "/docker-compose")
      : `${baseUrl}/docker-compose`;

  const parsed = new URL(cpuUrl.endsWith("/cpu") ? cpuUrl.replace(/\/cpu$/, "") : cpuUrl);
  const host = parsed.hostname;
  const port = parsed.port ? Number(parsed.port) : 443;

  // 3. TLS certificate fingerprint
  let tlsFingerprint: Buffer;
  try {
    tlsFingerprint = await getTlsCertFingerprint(host, port);
    checks.tls_cert_obtained = true;
    report.tls_fingerprint = tlsFingerprint.toString("hex");
  } catch (e: any) {
    errors.push(`Failed to get TLS certificate: ${e.message}`);
    checks.tls_cert_obtained = false;
    return makeResult("ERC-8004", { checks, report, errors });
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
    return makeResult("ERC-8004", { checks, report, errors });
  }

  const cpuResult = await checkCpuAttestation(cpuData, "", reloadAmdKds);
  checks.cpu_attestation_valid = cpuResult.valid;
  // Propagate the inner DCAP/QVL verification verdict for prominent display.
  if (cpuResult.checks.quote_verified !== undefined) {
    checks.cpu_quote_verified = cpuResult.checks.quote_verified;
  }
  report.cpu = cpuResult.report;
  report.cpu_type = cpuResult.attestationType;
  if (!cpuResult.valid) errors.push(...cpuResult.errors);

  // 5. TLS binding
  const reportDataHex: string = cpuResult.report.report_data ?? "";
  if (reportDataHex.length >= 64) {
    const firstHalf = reportDataHex.slice(0, 64);
    checks.tls_binding = firstHalf === tlsFingerprint.toString("hex");
    if (!checks.tls_binding) {
      errors.push(
        `TLS binding failed: report_data first half (${firstHalf.slice(0, 16)}...) ` +
          `!= TLS fingerprint (${tlsFingerprint.toString("hex").slice(0, 16)}...)`,
      );
    }
  } else {
    checks.tls_binding = false;
    errors.push("report_data too short for TLS binding check");
  }

  // 6. GPU quote (optional)
  let gpuPresent = false;
  let gpuData = "";
  try {
    const resp = await fetch(gpuUrl);
    if (resp.ok) {
      gpuData = await resp.text();
      const gpuJson = JSON.parse(gpuData);
      if ("error" in gpuJson) {
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
    const gpuResult = await checkNvidiaGpuAttestation(gpuData);
    checks.gpu_attestation_valid = gpuResult.valid;
    report.gpu = gpuResult.report;
    if (!gpuResult.valid) errors.push(...gpuResult.errors);

    const gpuJson = JSON.parse(gpuData);
    const gpuNonce: string = gpuJson.nonce ?? "";
    if (reportDataHex.length >= 128) {
      const secondHalf = reportDataHex.slice(64, 128);
      checks.gpu_binding = secondHalf === gpuNonce;
      if (!checks.gpu_binding) {
        errors.push(
          `GPU binding failed: report_data second half (${secondHalf.slice(0, 16)}...) ` +
            `!= GPU nonce (${gpuNonce.slice(0, 16)}...)`,
        );
      }
    } else {
      checks.gpu_binding = false;
      errors.push("report_data too short for GPU binding check");
    }
  }

  // 7. Workload verification
  try {
    const resp = await fetch(workloadUrl);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const dockerCompose = extractDockerCompose(await resp.text());
    checks.workload_fetched = true;

    const workloadResult = await verifyWorkload(cpuData, dockerCompose);
    checks.workload_verified = workloadResult.status === "authentic_match";
    report.workload = workloadResult;
    if (workloadResult.status === "authentic_mismatch") {
      errors.push("Workload mismatch: VM is authentic but docker-compose does not match");
    } else if (workloadResult.status === "not_authentic") {
      errors.push("Workload verification failed: not an authentic SecretVM");
    }
  } catch (e: any) {
    errors.push(`Failed to fetch workload: ${e.message}`);
    checks.workload_fetched = false;
  }

  // Overall validity
  const requiredChecks = [
    checks.metadata_valid,
    checks.tls_cert_obtained,
    checks.cpu_quote_fetched,
    checks.cpu_attestation_valid,
    checks.tls_binding,
    !!checks.workload_verified,
  ];
  if (gpuPresent) {
    requiredChecks.push(!!checks.gpu_attestation_valid);
    requiredChecks.push(!!checks.gpu_binding);
  }
  const valid = requiredChecks.every(Boolean);

  return makeResult("ERC-8004", { valid, checks, report, errors });
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
    return makeResult("ERC-8004", { checks, errors });
  }

  const result = await verifyAgent(metadata, reloadAmdKds);
  result.checks = { agent_resolved: true, ...result.checks };

  return result;
}
