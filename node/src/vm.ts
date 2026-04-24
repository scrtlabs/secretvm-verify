import { AttestationResult, makeResult, orderChecks } from "./types.js";
import { checkCpuAttestation } from "./cpu.js";
import { checkNvidiaGpuAttestation } from "./nvidia.js";
import { checkProofOfCloud as checkProofOfCloud_ } from "./proofOfCloud.js";
import { verifyWorkload } from "./workload.js";
import { extractDockerCompose, getTlsCertFingerprint } from "./url.js";

const SECRET_VM_PORT = 29343;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Re-export for backwards compatibility
export { extractDockerCompose };

export function parseVmUrl(url: string): { host: string; port: number } {
  if (!url.includes("://")) url = `https://${url}`;
  const parsed = new URL(url);
  return {
    host: parsed.hostname,
    port: parsed.port ? Number(parsed.port) : SECRET_VM_PORT,
  };
}

// ---------------------------------------------------------------------------
// Public
// ---------------------------------------------------------------------------

export async function checkSecretVm(
  url: string,
  product = "",
  reloadAmdKds = false,
  checkProofOfCloud = false,
): Promise<AttestationResult> {
  const errors: string[] = [];
  const checks: Record<string, boolean> = {};
  const report: Record<string, any> = {};

  let host: string;
  let port: number;
  try {
    ({ host, port } = parseVmUrl(url));
  } catch (e: any) {
    return makeResult("SECRET-VM", { errors: [e.message] });
  }

  const baseUrl = `https://${host}:${port}`;

  // 1. TLS certificate fingerprint
  let tlsFingerprint: Buffer;
  try {
    tlsFingerprint = await getTlsCertFingerprint(host, port);
    checks.tls_cert_fetched = true;
    report.tls_fingerprint = tlsFingerprint.toString("hex");
  } catch (e: any) {
    errors.push(`Failed to get TLS certificate: ${e.message}`);
    checks.tls_cert_fetched = false;
    return makeResult("SECRET-VM", { checks: orderChecks(checks), report, errors });
  }

  // 2. Fetch and verify CPU quote
  let cpuData: string;
  try {
    const resp = await fetch(`${baseUrl}/cpu`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    cpuData = await resp.text();
    checks.cpu_quote_fetched = true;
  } catch (e: any) {
    errors.push(`Failed to fetch CPU quote: ${e.message}`);
    checks.cpu_quote_fetched = false;
    return makeResult("SECRET-VM", { checks: orderChecks(checks), report, errors });
  }

  const cpuResult = await checkCpuAttestation(cpuData, product, reloadAmdKds);
  checks.cpu_quote_verified = cpuResult.valid;
  report.cpu = cpuResult.report;
  report.cpu_type = cpuResult.attestationType;
  if (!cpuResult.valid) {
    errors.push(...cpuResult.errors);
  }

  // 3. TLS binding: first 32 bytes of report_data == SHA-256(TLS cert)
  const reportDataHex: string = cpuResult.report.report_data ?? "";
  if (reportDataHex.length >= 64) {
    const firstHalf = reportDataHex.slice(0, 64);
    checks.tls_binding_verified = firstHalf === tlsFingerprint.toString("hex");
    if (!checks.tls_binding_verified) {
      errors.push(
        `TLS binding failed: report_data first half (${firstHalf.slice(0, 16)}...) ` +
          `!= TLS fingerprint (${tlsFingerprint.toString("hex").slice(0, 16)}...)`,
      );
    }
  } else {
    checks.tls_binding_verified = false;
    errors.push("report_data too short for TLS binding check");
  }

  // 4. Fetch GPU quote (optional)
  let gpuPresent = false;
  let gpuData = "";
  try {
    const resp = await fetch(`${baseUrl}/gpu`);
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
    const gpuResult = await checkNvidiaGpuAttestation(gpuData);
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

  // 6. Fetch and verify workload (docker-compose)
  try {
    const resp = await fetch(`${baseUrl}/docker-compose`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const dockerCompose = extractDockerCompose(await resp.text());
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

  // 7. Proof of cloud (opt-in): SCRT Labs' quote-parse endpoint identifies
  // the VM as a Secret VM. Disabled by default — pass checkProofOfCloud=true
  // (or --proof-of-cloud on the CLI) to include this check.
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
  if (gpuPresent) {
    requiredChecks.push(!!checks.gpu_quote_verified);
    requiredChecks.push(!!checks.gpu_binding_verified);
  }
  const valid = requiredChecks.every(Boolean);

  return makeResult("SECRET-VM", { valid, checks: orderChecks(checks), report, errors });
}
