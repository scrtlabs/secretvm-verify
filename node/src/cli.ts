#!/usr/bin/env node
import { readFileSync } from "node:fs";
import {
  checkSecretVm,
  checkCpuAttestation,
  checkTdxCpuAttestation,
  checkAmdCpuAttestation,
  checkNvidiaGpuAttestation,
  detectCpuQuoteType,
  resolveSecretVmVersion,
  resolveAmdSevVersion,
  verifyWorkload,
  formatWorkloadResult,
} from "./index.js";
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
  return args.find((a) => !a.startsWith("--"));
}

const raw = getFlag("--raw");
const product = getFlagValue("--product") ?? "";

const USAGE = `Usage: secretvm-verify <command> <value> [--product NAME] [--raw]

Commands:
  --secretvm <url>                  Verify a Secret VM (CPU + GPU + TLS binding)
  --cpu <file>                      Verify a CPU quote (auto-detect TDX vs SEV-SNP)
  --tdx <file>                      Verify an Intel TDX quote
  --sev <file>                      Verify an AMD SEV-SNP report
  --gpu <file>                      Verify an NVIDIA GPU attestation
  --resolve-version <file>          Resolve SecretVM version from TDX or AMD SEV-SNP quote
  --verify-workload <file> --compose <file>
                                    Verify TDX or AMD SEV-SNP workload against a docker-compose.yaml

Options:
  --product NAME       AMD product name (Genoa, Milan, Turin)
  --raw                Output raw JSON result

Examples:
  secretvm-verify --secretvm yellow-krill.vm.scrtlabs.com
  secretvm-verify --tdx cpu_quote.txt
  secretvm-verify --sev amd_cpu_quote.txt --product Genoa
  secretvm-verify --gpu gpu_attest.txt
  secretvm-verify --cpu cpu_quote.txt --raw
  secretvm-verify --resolve-version cpu_quote.txt
  secretvm-verify --verify-workload cpu_quote.txt --compose docker-compose.yaml`;

// Determine which command to run
let result: AttestationResult;

if (getFlag("--secretvm")) {
  const url = getFlagValue("--secretvm") ?? getPositional();
  if (!url) {
    console.log(USAGE);
    process.exit(1);
  }
  if (!raw) console.log(`Checking attestation for ${url} ...\n`);
  result = await checkSecretVm(url, product);
} else if (getFlag("--cpu")) {
  const file = getFlagValue("--cpu") ?? getPositional();
  if (!file) {
    console.log(USAGE);
    process.exit(1);
  }
  if (!raw) console.log(`Verifying CPU quote from ${file} ...\n`);
  result = await checkCpuAttestation(readFileSync(file, "utf8"), product);
} else if (getFlag("--tdx")) {
  const file = getFlagValue("--tdx") ?? getPositional();
  if (!file) {
    console.log(USAGE);
    process.exit(1);
  }
  if (!raw) console.log(`Verifying TDX quote from ${file} ...\n`);
  result = await checkTdxCpuAttestation(readFileSync(file, "utf8"));
} else if (getFlag("--sev")) {
  const file = getFlagValue("--sev") ?? getPositional();
  if (!file) {
    console.log(USAGE);
    process.exit(1);
  }
  if (!raw) console.log(`Verifying AMD SEV-SNP report from ${file} ...\n`);
  result = await checkAmdCpuAttestation(readFileSync(file, "utf8"), product);
} else if (getFlag("--gpu")) {
  const file = getFlagValue("--gpu") ?? getPositional();
  if (!file) {
    console.log(USAGE);
    process.exit(1);
  }
  if (!raw) console.log(`Verifying NVIDIA GPU attestation from ${file} ...\n`);
  result = await checkNvidiaGpuAttestation(readFileSync(file, "utf8"));
} else if (getFlag("--resolve-version")) {
  const file = getFlagValue("--resolve-version") ?? getPositional();
  if (!file) {
    console.log(USAGE);
    process.exit(1);
  }
  const quoteData = readFileSync(file, "utf8");
  const quoteType = detectCpuQuoteType(quoteData);
  if (quoteType === "SEV-SNP") {
    // Step 1: cryptographic quote verification
    const quoteResult = await checkAmdCpuAttestation(quoteData, product);
    // Step 2: registry lookup
    const version = resolveAmdSevVersion(quoteData);
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
    const version = resolveSecretVmVersion(quoteData);
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
} else if (getFlag("--verify-workload")) {
  const quoteFile = getFlagValue("--verify-workload") ?? getPositional();
  const composeFile = getFlagValue("--compose");
  if (!quoteFile || !composeFile) {
    console.log(USAGE);
    process.exit(1);
  }
  const quoteData = readFileSync(quoteFile, "utf8");
  const composeData = readFileSync(composeFile, "utf8");
  const quoteType = detectCpuQuoteType(quoteData);
  if (quoteType === "SEV-SNP") {
    // Step 1: cryptographic quote verification
    const quoteResult = await checkAmdCpuAttestation(quoteData, product);
    if (raw) {
      const workloadResult = verifyWorkload(quoteData, composeData);
      console.log(JSON.stringify({ quote: quoteResult, workload: workloadResult }, null, 2));
      process.exit(quoteResult.valid && workloadResult.status === "authentic_match" ? 0 : 1);
    }
    if (!quoteResult.valid) {
      console.log("🚫 Quote cryptographic verification failed");
      process.exit(1);
    }
    // Step 2: registry lookup — confirms this is a known SecretVM
    const version = resolveAmdSevVersion(quoteData);
    if (!version) {
      console.log("🚫 SecretVM artifacts not found in registry (unknown version)");
      process.exit(1);
    }
    console.log(`✅ Authentic SecretVM confirmed: ${version.vm_type}/${version.template_name} ${version.artifacts_ver}`);
    // Step 3: workload (compose hash) verification
    const workloadResult = verifyWorkload(quoteData, composeData);
    if (workloadResult.status === "authentic_match") {
      console.log("✅ Confirmed that the VM is running the specified docker-compose.yaml");
    } else {
      console.log("🚫 Attestation does not match the specified docker-compose.yaml");
    }
    process.exit(workloadResult.status === "authentic_match" ? 0 : 1);
  } else {
    const quoteResult = await checkTdxCpuAttestation(quoteData);
    if (raw) {
      const workloadResult = verifyWorkload(quoteData, composeData);
      console.log(JSON.stringify({ quote: quoteResult, workload: workloadResult }, null, 2));
      process.exit(quoteResult.valid && workloadResult.status === "authentic_match" ? 0 : 1);
    }
    if (!quoteResult.valid) {
      console.log("🚫 Attestation doesn't belong to an authentic SecretVM");
      process.exit(1);
    }
    const workloadResult = verifyWorkload(quoteData, composeData);
    console.log(formatWorkloadResult(workloadResult));
    process.exit(workloadResult.status === "authentic_match" ? 0 : 1);
  }
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

console.log("Checks:");
for (const [name, passed] of Object.entries(result.checks)) {
  if (name === "gpu_quote_fetched" && !passed) {
    console.log(`  ${"gpu:".padEnd(35)} GPU not present`);
    continue;
  }
  const status = passed ? "PASS" : "FAIL";
  console.log(`  ${(name + ":").padEnd(35)} ${status}`);
}

const report = result.report;

// Secret VM specific fields
if (report.cpu_type) console.log(`\nCPU type: ${report.cpu_type}`);
if (report.tls_fingerprint) console.log(`TLS fingerprint: ${report.tls_fingerprint}`);

// CPU fields (direct or nested under cpu)
const cpu = report.cpu ?? report;
if (cpu.report_data) console.log(`Report data: ${cpu.report_data}`);
if (cpu.measurement) console.log(`Measurement: ${cpu.measurement}`);
if (cpu.mr_td) console.log(`MR TD: ${cpu.mr_td}`);
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

if (result.errors.length > 0) {
  console.log("\nErrors:");
  for (const err of result.errors) console.log(`  - ${err}`);
}

console.log(`\n${result.valid ? "PASSED" : "FAILED"}`);
process.exit(result.valid ? 0 : 1);
