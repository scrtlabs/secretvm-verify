#!/usr/bin/env node
import { readFileSync } from "node:fs";
import {
  checkSecretVm,
  checkCpuAttestation,
  checkTdxCpuAttestation,
  checkSevCpuAttestation,
  checkNvidiaGpuAttestation,
  detectCpuQuoteType,
  resolveSecretVmVersion,
  resolveAmdSevVersion,
  verifyWorkload,
  formatWorkloadResult,
} from "./index.js";
import { resolveAgent, verifyAgent, checkAgent } from "./agent.js";
import { extractDockerCompose } from "./vm.js";
import type { AttestationResult } from "./types.js";

const args = process.argv.slice(2);

function getFlag(name: string): boolean {
  return args.includes(name);
}

function getFlagValue(name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  return undefined;
}

function getPositional(): string | undefined {
  return args.find((a) => !a.startsWith("--") && a !== "-v" && a !== "-rv" && a !== "-vw");
}

const raw = getFlag("--raw");
const verbose = getFlag("--verbose") || getFlag("-v");
const product = getFlagValue("--product") ?? "";
const vmUrl = getFlagValue("--vm");
// `--secretvm` defaults to a terse output (verdict + errors only). Use
// `--verbose` (or `-v`) to also show the per-check breakdown and report
// fields. Other modes (--cpu, --tdx, --sev, --gpu, etc.) keep their
// detailed default output.
const isSecretvm = getFlag("--secretvm");

const SECRET_VM_PORT = 29343;

async function fetchFromVm(endpoint: string): Promise<string> {
  let url = vmUrl!;
  if (!url.includes("://")) url = `https://${url}`;
  const parsed = new URL(url);
  const port = parsed.port || SECRET_VM_PORT;
  const base = `https://${parsed.hostname}:${port}`;
  const resp = await fetch(`${base}/${endpoint}`);
  if (!resp.ok) throw new Error(`HTTP ${resp.status} from ${base}/${endpoint}`);
  const text = await resp.text();
  if (endpoint === "docker-compose") return extractDockerCompose(text);
  return text;
}

function getQuoteData(flagName: string, shortFlag?: string): string {
  if (vmUrl) return ""; // placeholder, will be fetched async
  const file = getFlagValue(flagName) ?? (shortFlag ? getFlagValue(shortFlag) : undefined) ?? getPositional();
  if (!file) {
    console.log(USAGE);
    process.exit(1);
  }
  return readFileSync(file, "utf8");
}

async function getCpuQuote(flagName: string, shortFlag?: string): Promise<string> {
  if (vmUrl) return fetchFromVm("cpu");
  const file = getFlagValue(flagName) ?? (shortFlag ? getFlagValue(shortFlag) : undefined) ?? getPositional();
  if (!file) { console.log(USAGE); process.exit(1); }
  return readFileSync(file, "utf8");
}

async function getGpuQuote(flagName: string): Promise<string> {
  if (vmUrl) return fetchFromVm("gpu");
  const file = getFlagValue(flagName) ?? getPositional();
  if (!file) { console.log(USAGE); process.exit(1); }
  return readFileSync(file, "utf8");
}

const USAGE = `Usage: secretvm-verify <command> <value> [--product NAME] [--raw] [--verbose|-v]

Commands:
  --secretvm <url>                  Verify a Secret VM (CPU + GPU + TLS binding)
  --cpu <file|--vm url>             Verify a CPU quote (auto-detect TDX vs SEV-SNP)
  --tdx <file|--vm url>             Verify an Intel TDX quote
  --sev <file|--vm url>             Verify an AMD SEV-SNP report
  --gpu <file|--vm url>             Verify an NVIDIA GPU attestation
  --resolve-version, -rv <file|--vm url>
                                    Resolve SecretVM version from TDX or AMD SEV-SNP quote
  --verify-workload, -vw <file|--vm url> [--compose <file>]
                                    Verify workload against a docker-compose (fetched from VM if --vm)
  --check-agent <id> --chain <name>
                                    Resolve and verify an ERC-8004 agent on-chain
  --agent <file>                    Verify an ERC-8004 agent from a metadata JSON file

Options:
  --vm <url>           Fetch quote from a VM instead of a file (works with --cpu, --tdx, --sev, --gpu, -rv, -vw)
  --chain NAME         Chain name for --check-agent (e.g. base, ethereum, arbitrum)
  --product NAME       AMD product name (Genoa, Milan, Turin)
  --raw                Output raw JSON result
  --verbose, -v        Print all attestation report fields

Examples:
  secretvm-verify --secretvm yellow-krill.vm.scrtlabs.com
  secretvm-verify --tdx cpu_quote.txt
  secretvm-verify --tdx --vm blue-moose.vm.scrtlabs.com
  secretvm-verify --cpu --vm blue-moose.vm.scrtlabs.com
  secretvm-verify --sev amd_cpu_quote.txt --product Genoa
  secretvm-verify --gpu gpu_attest.txt
  secretvm-verify --cpu cpu_quote.txt --raw
  secretvm-verify -rv --vm blue-moose.vm.scrtlabs.com
  secretvm-verify -vw --vm blue-moose.vm.scrtlabs.com
  secretvm-verify --verify-workload cpu_quote.txt --compose docker-compose.yaml
  secretvm-verify --check-agent 38114 --chain base
  secretvm-verify --check-agent 38114 --chain base -v
  secretvm-verify --agent metadata.json`;

function formatError(err: any): string {
  const cause = err?.cause;
  if (cause?.code === "ECONNREFUSED") {
    return `Could not connect to ${cause.address}:${cause.port} - Connection refused`;
  }
  if (cause?.code === "ENOTFOUND") {
    return `Could not resolve hostname: ${cause.hostname}`;
  }
  if (cause?.code === "ETIMEDOUT" || cause?.code === "ECONNRESET") {
    return `Connection to ${cause.address || "host"}:${cause.port || ""} timed out`;
  }
  if (err?.message) return err.message;
  return String(err);
}

// Determine which command to run
let result: AttestationResult;

try {

if (getFlag("--secretvm")) {
  const url = getFlagValue("--secretvm") ?? getPositional();
  if (!url) {
    console.log(USAGE);
    process.exit(1);
  }
  if (!raw) console.log(`Checking attestation for ${url} ...\n`);
  result = await checkSecretVm(url, product);
} else if (getFlag("--cpu")) {
  const quoteData = await getCpuQuote("--cpu");
  const source = vmUrl ? vmUrl : getFlagValue("--cpu") ?? getPositional();
  if (!raw) console.log(`Verifying CPU quote from ${source} ...\n`);
  result = await checkCpuAttestation(quoteData, product);
} else if (getFlag("--tdx")) {
  const quoteData = await getCpuQuote("--tdx");
  const source = vmUrl ? vmUrl : getFlagValue("--tdx") ?? getPositional();
  if (!raw) console.log(`Verifying TDX quote from ${source} ...\n`);
  result = await checkTdxCpuAttestation(quoteData);
} else if (getFlag("--sev")) {
  const quoteData = await getCpuQuote("--sev");
  const source = vmUrl ? vmUrl : getFlagValue("--sev") ?? getPositional();
  if (!raw) console.log(`Verifying AMD SEV-SNP report from ${source} ...\n`);
  result = await checkSevCpuAttestation(quoteData, product);
} else if (getFlag("--gpu")) {
  const quoteData = await getGpuQuote("--gpu");
  const source = vmUrl ? vmUrl : getFlagValue("--gpu") ?? getPositional();
  if (!raw) console.log(`Verifying NVIDIA GPU attestation from ${source} ...\n`);
  result = await checkNvidiaGpuAttestation(quoteData);
} else if (getFlag("--resolve-version") || getFlag("-rv")) {
  const quoteData = await getCpuQuote("--resolve-version", "-rv");
  const quoteType = detectCpuQuoteType(quoteData);
  if (quoteType === "SEV-SNP") {
    // Step 1: cryptographic quote verification
    const quoteResult = await checkSevCpuAttestation(quoteData, product);
    // Step 2: registry lookup
    const version = await resolveAmdSevVersion(quoteData);
    if (raw) {
      console.log(JSON.stringify({ quote: quoteResult, version }, null, 2));
      process.exit(quoteResult.valid && !!version ? 0 : 1);
    }
    if (!quoteResult.valid) {
      console.log("🚫 Quote cryptographic verification failed");
      process.exit(1);
    }
    if (version) {
      console.log(`✅ Authentic SecretVM confirmed`);
      console.log(`Template: ${version.template_name}`);
      console.log(`VM type:  ${version.vm_type}`);
      console.log(`Version:  ${version.artifacts_ver}`);
    } else {
      console.log("🚫 SecretVM artifacts not found in registry (unknown version)");
    }
    process.exit(quoteResult.valid && !!version ? 0 : 1);
  } else {
    const quoteResult = await checkTdxCpuAttestation(quoteData);
    const version = await resolveSecretVmVersion(quoteData);
    if (raw) {
      console.log(JSON.stringify({ quote: quoteResult, version }, null, 2));
      process.exit(quoteResult.valid && !!version ? 0 : 1);
    }
    if (!quoteResult.valid) {
      console.log("🚫 Attestation doesn't belong to an authentic SecretVM");
      process.exit(1);
    }
    if (version) {
      console.log(`Template: ${version.template_name}`);
      console.log(`Version:  ${version.artifacts_ver}`);
    } else {
      console.log("No matching SecretVM version found in registry.");
    }
    process.exit(!!version ? 0 : 1);
  }
} else if (getFlag("--verify-workload") || getFlag("-vw")) {
  const quoteData = await getCpuQuote("--verify-workload", "-vw");
  let composeData: string;
  if (vmUrl) {
    composeData = await fetchFromVm("docker-compose");
  } else {
    const composeFile = getFlagValue("--compose");
    if (!composeFile) { console.log(USAGE); process.exit(1); }
    composeData = readFileSync(composeFile, "utf8");
  }
  const quoteType = detectCpuQuoteType(quoteData);
  if (quoteType === "SEV-SNP") {
    // Step 1: cryptographic quote verification
    const quoteResult = await checkSevCpuAttestation(quoteData, product);
    if (raw) {
      const workloadResult = await verifyWorkload(quoteData, composeData);
      console.log(JSON.stringify({ quote: quoteResult, workload: workloadResult }, null, 2));
      process.exit(quoteResult.valid && workloadResult.status === "authentic_match" ? 0 : 1);
    }
    if (!quoteResult.valid) {
      console.log("🚫 Quote cryptographic verification failed");
      process.exit(1);
    }
    // Step 2: registry lookup — confirms this is a known SecretVM
    const version = await resolveAmdSevVersion(quoteData);
    if (!version) {
      console.log("🚫 SecretVM artifacts not found in registry (unknown version)");
      process.exit(1);
    }
    console.log(`✅ Authentic SecretVM confirmed: ${version.vm_type}/${version.template_name} ${version.artifacts_ver}`);
    // Step 3: workload (compose hash) verification
    const workloadResult = await verifyWorkload(quoteData, composeData);
    if (workloadResult.status === "authentic_match") {
      console.log(`✅ Confirmed that the VM is running the docker-compose.yaml specified at ${vmUrl}:29343/docker-compose`);
    } else {
      const src = vmUrl ? `the docker-compose.yaml specified at ${vmUrl}:29343/docker-compose` : "the specified docker-compose.yaml";
      console.log(`🚫 Attestation does not match ${src}`);
    }
    process.exit(workloadResult.status === "authentic_match" ? 0 : 1);
  } else {
    const quoteResult = await checkTdxCpuAttestation(quoteData);
    if (raw) {
      const workloadResult = await verifyWorkload(quoteData, composeData);
      console.log(JSON.stringify({ quote: quoteResult, workload: workloadResult }, null, 2));
      process.exit(quoteResult.valid && workloadResult.status === "authentic_match" ? 0 : 1);
    }
    if (!quoteResult.valid) {
      console.log("🚫 Attestation doesn't belong to an authentic SecretVM");
      process.exit(1);
    }
    const workloadResult = await verifyWorkload(quoteData, composeData);
    console.log(formatWorkloadResult(workloadResult, vmUrl));
    process.exit(workloadResult.status === "authentic_match" ? 0 : 1);
  }
} else if (getFlag("--check-agent")) {
  const id = getFlagValue("--check-agent");
  const chain = getFlagValue("--chain");
  if (!id || !chain) {
    console.log(USAGE);
    process.exit(1);
  }
  if (!raw) console.log(`Resolving and verifying agent ${id} on ${chain} ...\n`);
  result = await checkAgent(Number(id), chain);
} else if (getFlag("--agent")) {
  const file = getFlagValue("--agent") ?? getPositional();
  if (!file) {
    console.log(USAGE);
    process.exit(1);
  }
  const metadata = JSON.parse(readFileSync(file, "utf8"));
  if (!raw) console.log(`Verifying agent "${metadata.name}" ...\n`);
  result = await verifyAgent(metadata);
} else {
  // Legacy: bare URL defaults to --secretvm
  const url = getPositional();
  if (!url) {
    console.log(USAGE);
    process.exit(1);
  }
  if (!raw) console.log(`Checking attestation for ${url} ...\n`);
  result = await checkSecretVm(url, product);
}

// Output
if (raw) {
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.valid ? 0 : 1);
}

// Prominent top-level cryptographic attestation verdict.
// Prefer the QVL `quote_verified` signal (direct CPU/TDX call), or its
// propagated form `cpu_quote_verified` from a wrapper (checkSecretVm,
// verifyAgent). Fall back to other CPU verdict signals so this line works
// across all attestation types.
function getAttestationVerdict(r: AttestationResult): boolean | null {
  const c = r.checks;
  if (c.quote_verified !== undefined) return !!c.quote_verified;
  if (c.cpu_quote_verified !== undefined) return !!c.cpu_quote_verified;
  if (c.report_signature_valid !== undefined) return !!c.report_signature_valid;
  if (c.cpu_attestation_valid !== undefined) return !!c.cpu_attestation_valid;
  return null;
}
const verdict = getAttestationVerdict(result);
if (verdict !== null) {
  const label = verdict ? "PASS" : "FAIL";
  const icon = verdict ? "✅" : "🚫";
  console.log(`${icon} Attestation verified: ${label}\n`);
}

// The per-check PASS/FAIL breakdown is always shown. The report-field
// details (CPU/TLS/RTMR/TCB/GPU specifics) are hidden in `--secretvm` mode
// without `--verbose`. Other modes (--cpu, --tdx, --sev, --gpu,
// --check-agent, etc.) always show the report fields.
const showReportFields = !isSecretvm || verbose;
const report = result.report;

console.log("Checks:");
for (const [name, passed] of Object.entries(result.checks)) {
  if (name === "gpu_quote_fetched" && !passed) {
    console.log(`  ${"gpu:".padEnd(35)} GPU not present`);
    continue;
  }
  const status = passed ? "PASS" : "FAIL";
  console.log(`  ${(name + ":").padEnd(35)} ${status}`);
}

if (showReportFields) {
  // Secret VM specific fields
  if (report.cpu_type) console.log(`\nCPU type: ${report.cpu_type}`);
  if (report.tls_fingerprint) console.log(`TLS fingerprint: ${report.tls_fingerprint}`);

  // CPU fields (direct or nested under cpu)
  const cpu = report.cpu ?? report;
  if (cpu.report_data) console.log(`Report data: ${cpu.report_data}`);
  if (cpu.measurement) console.log(`Measurement: ${cpu.measurement}`);
  if (cpu.mr_td) console.log(`MR TD:  ${cpu.mr_td}`);
  if (cpu.rt_mr0) console.log(`RTMR0:  ${cpu.rt_mr0}`);
  if (cpu.rt_mr1) console.log(`RTMR1:  ${cpu.rt_mr1}`);
  if (cpu.rt_mr2) console.log(`RTMR2:  ${cpu.rt_mr2}`);
  if (cpu.rt_mr3) console.log(`RTMR3:  ${cpu.rt_mr3}`);
  if (cpu.tcb_status) console.log(`TCB status: ${cpu.tcb_status}`);
  if (cpu.product) console.log(`AMD product: ${cpu.product}`);
  if (cpu.chip_id) console.log(`Chip ID: ${cpu.chip_id}`);
  if (cpu.fmspc) console.log(`FMSPC: ${cpu.fmspc}`);

  // GPU fields (direct or nested under gpu)
  const gpu = report.gpu ?? report;
  if (gpu.overall_result !== undefined) console.log(`\nGPU overall result: ${gpu.overall_result}`);
  if (gpu.gpus) {
    for (const [gpuId, info] of Object.entries<any>(gpu.gpus)) {
      console.log(`\n${gpuId}:`);
      console.log(`  Model: ${info.model}`);
      console.log(`  Driver: ${info.driver_version}`);
      console.log(`  Secure boot: ${info.secure_boot}`);
    }
  }
}

// Verbose: print all report fields
if (verbose) {
  console.log("\nAll attestation report fields:");
  for (const [key, value] of Object.entries(report)) {
    if (typeof value === "object" && value !== null) {
      console.log(`  ${key}:`);
      for (const [subKey, subValue] of Object.entries(value)) {
        if (typeof subValue === "object" && subValue !== null) {
          console.log(`    ${subKey}: ${JSON.stringify(subValue)}`);
        } else {
          console.log(`    ${subKey}: ${subValue}`);
        }
      }
    } else {
      console.log(`  ${key}: ${value}`);
    }
  }
}

if (result.errors.length > 0) {
  console.log("\nErrors:");
  for (const err of result.errors) console.log(`  - ${err}`);
}

console.log(`\n${result.valid ? "PASSED" : "FAILED"}`);
process.exit(result.valid ? 0 : 1);

} catch (err: any) {
  console.error(`Error: ${formatError(err)}`);
  process.exit(1);
}
