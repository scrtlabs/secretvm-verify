export interface AttestationResult {
  valid: boolean;
  attestationType: string;
  checks: Record<string, boolean>;
  report: Record<string, any>;
  errors: string[];
}

export function makeResult(
  attestationType: string,
  overrides: Partial<AttestationResult> = {},
): AttestationResult {
  return {
    valid: false,
    attestationType,
    checks: {},
    report: {},
    errors: [],
    ...overrides,
  };
}

// Canonical ordering for the per-check list. Keys are inserted into the final
// `result.checks` object in this order; any keys not listed are appended at
// the end (future-proofing).
const CHECK_ORDER: string[] = [
  "metadata_valid",
  "cpu_quote_fetched",
  "tls_cert_fetched",
  // TDX-specific detail keys (present on direct checkTdxCpuAttestation results)
  "quote_parsed",
  "quote_verified",
  // SEV-specific detail keys (present on direct checkSevCpuAttestation results)
  "report_parsed",
  "vcek_fetched",
  "cert_chain_valid",
  "crl_check_passed",
  "report_signature_valid",
  // VM-level rollup (present on checkSecretVm results)
  "cpu_quote_verified",
  "tls_binding_verified",
  "gpu_quote_fetched",
  "gpu_quote_verified",
  "gpu_binding_verified",
  "workload_fetched",
  "workload_binding_verified",
  "proof_of_cloud_verified",
];

export function orderChecks(
  checks: Record<string, boolean>,
): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const key of CHECK_ORDER) {
    if (key in checks) out[key] = checks[key];
  }
  for (const key of Object.keys(checks)) {
    if (!(key in out)) out[key] = checks[key];
  }
  return out;
}

export interface AgentService {
  name: string;
  endpoint: string;
  description?: string;
}

export interface AgentMetadata {
  name: string;
  description?: string;
  supportedTrust: string[];
  services: AgentService[];
  image?: string;
  type?: string;
  active?: boolean;
  x402Support?: boolean;
  attributes?: Record<string, any>;
  raw?: Record<string, any>;
}
