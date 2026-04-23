#!/usr/bin/env node
import { readFileSync } from "node:fs";
import {
  checkSecretVm,
  checkCpuAttestation,
  checkTdxCpuAttestation,
  checkSevCpuAttestation,
  checkNvidiaGpuAttestation,
  checkProofOfCloud,
  detectCpuQuoteType,
  resolveSecretVmVersion,
  resolveAmdSevVersion,
  verifyWorkload,
  formatWorkloadResult,
} from "./index.js";
import { resolveAgent, verifyAgent, checkAgent } from "./agent.js";
import { extractDockerCompose } from "./vm.js";
import { orderChecks } from "./types.js";
import type { AttestationResult } from "./types.js";

async function mergeProofOfCloud(
  result: AttestationResult,
  quote: string,
): Promise<AttestationResult> {
  const poc = await checkProofOfCloud(quote);
  result.checks.proof_of_cloud_verified = poc.valid;
  result.checks = orderChecks(result.checks);
  if (poc.report.proof_of_cloud !== undefined) {
    result.report.proof_of_cloud = poc.report.proof_of_cloud;
  }
  if (!poc.valid) {
    result.errors.push(...poc.errors);
    result.valid = false;
  }
  return result;
}

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
const json = getFlag("--json");
const jsonOut = raw || json;
const verbose = getFlag("--verbose") || getFlag("-v");

function minimalJson(result: AttestationResult): object {
  const { report: _report, ...rest } = result;
  return rest;
}
const product = getFlagValue("--product") ?? "";
const vmUrl = getFlagValue("--vm");
// `--reload-amd-kds` bypasses the local AMD KDS cache and re-fetches
// VCEK, AMD CA cert chain, and CRL from kdsintf.amd.com. No effect on TDX.
const reloadAmdKds = getFlag("--reload-amd-kds");
// `--docker-files <path>` points at a tar archive of Dockerfiles baked into
// the VM image. On TDX the SHA-256 digest becomes RTMR3 log[2]; on SEV-SNP
// it is appended to the kernel cmdline as `docker_additional_files_hash=...`.
// `--docker-files-sha256 <hex>` supplies the digest directly (skip the read).
const dockerFilesPath = getFlagValue("--docker-files");
const dockerFilesSha256 = getFlagValue("--docker-files-sha256");

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

const USAGE = `Usage: secretvm-verify <command> <value> [--product NAME] [--json|--raw] [--verbose|-v]

Commands:
  --secretvm <url>                  Verify a Secret VM (CPU + GPU + TLS binding)
  --cpu <file|--vm url>             Verify a CPU quote (auto-detect TDX vs SEV-SNP)
  --tdx <file|--vm url>             Verify an Intel TDX quote
  --sev <file|--vm url>             Verify an AMD SEV-SNP report
  --gpu <file|--vm url>             Verify an NVIDIA GPU attestation
  --resolve-version, -rv <file|--vm url>
                                    Resolve SecretVM version from TDX or AMD SEV-SNP quote
  --verify-workload, -vw <file|--vm url> [--compose <file>] [--docker-files <tar> | --docker-files-sha256 <hex>]
                                    Verify workload against a docker-compose (fetched from VM if --vm).
                                    --docker-files accepts a path to the Dockerfiles archive; its SHA-256 is
                                    computed client-side. --docker-files-sha256 supplies the digest directly
                                    (skips the file read). On TDX the digest extends RTMR3; on SEV-SNP it is
                                    appended to the kernel cmdline that feeds the launch measurement.
  --check-agent <id> --chain <name>
                                    Resolve and verify an ERC-8004 agent on-chain
  --agent <file>                    Verify an ERC-8004 agent from a metadata JSON file

Options:
  --vm <url>           Fetch quote from a VM instead of a file (works with --cpu, --tdx, --sev, --gpu, -rv, -vw)
  --chain NAME         Chain name for --check-agent (e.g. base, ethereum, arbitrum)
  --product NAME       AMD product name (Genoa, Milan, Turin)
  --json               Output minimal JSON (valid, checks, errors) — omits the report fields
  --raw                Output full JSON result (includes the parsed report fields)
  --verbose, -v        Print all attestation report fields (text mode only)
  --reload-amd-kds     Bypass the local AMD KDS cache and re-fetch VCEK,
                       cert chain, and CRL from kdsintf.amd.com (no effect on TDX)

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
  secretvm-verify --verify-workload cpu_quote.txt --compose docker-compose.yaml --docker-files docker-files.tar
  secretvm-verify --verify-workload cpu_quote.txt --compose docker-compose.yaml --docker-files-sha256 <hex>
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
    if (!jsonOut) console.log(`Verifying ${url}\n`);
    result = await checkSecretVm(url, product, reloadAmdKds);
  } else if (getFlag("--cpu")) {
    const quoteData = await getCpuQuote("--cpu");
    const source = vmUrl ? vmUrl : getFlagValue("--cpu") ?? getPositional();
    if (!jsonOut) console.log(`Verifying CPU quote from ${source} ...\n`);
    result = await checkCpuAttestation(quoteData, product, reloadAmdKds);
    result = await mergeProofOfCloud(result, quoteData);
  } else if (getFlag("--tdx")) {
    const quoteData = await getCpuQuote("--tdx");
    const source = vmUrl ? vmUrl : getFlagValue("--tdx") ?? getPositional();
    if (!jsonOut) console.log(`Verifying TDX quote from ${source} ...\n`);
    result = await checkTdxCpuAttestation(quoteData);
    result = await mergeProofOfCloud(result, quoteData);
  } else if (getFlag("--sev")) {
    const quoteData = await getCpuQuote("--sev");
    const source = vmUrl ? vmUrl : getFlagValue("--sev") ?? getPositional();
    if (!jsonOut) console.log(`Verifying AMD SEV-SNP report from ${source} ...\n`);
    result = await checkSevCpuAttestation(quoteData, product, reloadAmdKds);
    result = await mergeProofOfCloud(result, quoteData);
  } else if (getFlag("--gpu")) {
    const quoteData = await getGpuQuote("--gpu");
    const source = vmUrl ? vmUrl : getFlagValue("--gpu") ?? getPositional();
    if (!jsonOut) console.log(`Verifying NVIDIA GPU attestation from ${source} ...\n`);
    result = await checkNvidiaGpuAttestation(quoteData);
  } else if (getFlag("--resolve-version") || getFlag("-rv")) {
    const quoteData = await getCpuQuote("--resolve-version", "-rv");
    const quoteType = detectCpuQuoteType(quoteData);
    if (quoteType === "SEV-SNP") {
      // Step 1: cryptographic quote verification
      const quoteResult = await checkSevCpuAttestation(quoteData, product, reloadAmdKds);
      // Step 2: registry lookup
      const version = await resolveAmdSevVersion(quoteData);
      if (raw) {
        console.log(JSON.stringify({ quote: quoteResult, version }, null, 2));
        process.exit(quoteResult.valid && !!version ? 0 : 1);
      }
      if (json) {
        console.log(JSON.stringify({ quote: minimalJson(quoteResult), version }, null, 2));
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
      if (json) {
        console.log(JSON.stringify({ quote: minimalJson(quoteResult), version }, null, 2));
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
    // Optional docker-files input. Either read the archive and compute SHA-256,
    // or accept a precomputed digest. For TDX the digest becomes RTMR3 log[2];
    // for SEV it is appended as `docker_additional_files_hash=<hex>` to the
    // kernel cmdline that feeds the launch measurement.
    const dockerFilesInput: { dockerFiles?: Buffer; dockerFilesSha256?: string } = {};
    if (dockerFilesSha256) {
      dockerFilesInput.dockerFilesSha256 = dockerFilesSha256;
    } else if (dockerFilesPath) {
      dockerFilesInput.dockerFiles = readFileSync(dockerFilesPath);
    }
    const quoteType = detectCpuQuoteType(quoteData);
    if (quoteType === "SEV-SNP") {
      // Step 1: cryptographic quote verification
      const quoteResult = await checkSevCpuAttestation(quoteData, product, reloadAmdKds);
      if (raw) {
        const workloadResult = await verifyWorkload(quoteData, composeData, dockerFilesInput);
        console.log(JSON.stringify({ quote: quoteResult, workload: workloadResult }, null, 2));
        process.exit(quoteResult.valid && workloadResult.status === "authentic_match" ? 0 : 1);
      }
      if (json) {
        const workloadResult = await verifyWorkload(quoteData, composeData, dockerFilesInput);
        console.log(JSON.stringify({ quote: minimalJson(quoteResult), workload: workloadResult }, null, 2));
        process.exit(quoteResult.valid && workloadResult.status === "authentic_match" ? 0 : 1);
      }
      if (!quoteResult.valid) {
        console.log("🚫 Quote cryptographic verification failed");
        process.exit(1);
      }
      // Workload verification — authoritative; also identifies VM version
      const workloadResult = await verifyWorkload(quoteData, composeData, dockerFilesInput);
      const src = vmUrl ? `the docker-compose.yaml specified at ${vmUrl}:29343/docker-compose` : "the specified docker-compose.yaml";
      if (workloadResult.status === "authentic_match") {
        console.log(`✅ Authentic SecretVM confirmed: ${workloadResult.template_name} ${workloadResult.artifacts_ver} (${workloadResult.env})`);
        console.log(`✅ Confirmed that the VM is running ${src}`);
      } else if (workloadResult.status === "authentic_mismatch") {
        console.log(`✅ Authentic SecretVM confirmed: ${workloadResult.template_name} ${workloadResult.artifacts_ver} (${workloadResult.env})`);
        console.log(`🚫 Attestation does not match ${src}`);
      } else {
        // not_authentic: try version lookup to give a richer error message
        const version = await resolveAmdSevVersion(quoteData);
        if (version) {
          console.log(`✅ Authentic SecretVM (${version.vm_type}/${version.template_name} ${version.artifacts_ver})`);
          console.log(`🚫 Attestation does not match ${src}`);
        } else {
          console.log("🚫 SecretVM artifacts not found in registry");
        }
      }
      process.exit(workloadResult.status === "authentic_match" ? 0 : 1);
    } else {
      const quoteResult = await checkTdxCpuAttestation(quoteData);
      if (raw) {
        const workloadResult = await verifyWorkload(quoteData, composeData, dockerFilesInput);
        console.log(JSON.stringify({ quote: quoteResult, workload: workloadResult }, null, 2));
        process.exit(quoteResult.valid && workloadResult.status === "authentic_match" ? 0 : 1);
      }
      if (json) {
        const workloadResult = await verifyWorkload(quoteData, composeData, dockerFilesInput);
        console.log(JSON.stringify({ quote: minimalJson(quoteResult), workload: workloadResult }, null, 2));
        process.exit(quoteResult.valid && workloadResult.status === "authentic_match" ? 0 : 1);
      }
      if (!quoteResult.valid) {
        console.log("🚫 Attestation doesn't belong to an authentic SecretVM");
        process.exit(1);
      }
      const workloadResult = await verifyWorkload(quoteData, composeData, dockerFilesInput);
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
    if (!jsonOut) console.log(`Resolving and verifying agent ${id} on ${chain} ...\n`);
    result = await checkAgent(Number(id), chain, reloadAmdKds);
  } else if (getFlag("--agent")) {
    const file = getFlagValue("--agent") ?? getPositional();
    if (!file) {
      console.log(USAGE);
      process.exit(1);
    }
    const metadata = JSON.parse(readFileSync(file, "utf8"));
    if (!jsonOut) console.log(`Verifying agent "${metadata.name}" ...\n`);
    result = await verifyAgent(metadata, reloadAmdKds);
  } else {
    // Legacy: bare URL defaults to --secretvm
    const url = getPositional();
    if (!url) {
      console.log(USAGE);
      process.exit(1);
    }
    if (!jsonOut) console.log(`Verifying ${url}\n`);
    result = await checkSecretVm(url, product, reloadAmdKds);
  }

  // Output
  if (raw) {
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 1);
  }
  if (json) {
    console.log(JSON.stringify(minimalJson(result), null, 2));
    process.exit(result.valid ? 0 : 1);
  }

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

  if (verbose) {
    // For direct --tdx/--sev calls the CPU fields live at report top-level.
    // After mergeProofOfCloud splices proof_of_cloud into report, we must
    // exclude it from the CPU quote dump or it renders twice.
    let cpuQuote: any = null;
    if (report.cpu) {
      cpuQuote = report.cpu;
    } else if (["TDX", "SEV-SNP"].includes(result.attestationType)) {
      const { proof_of_cloud: _poc, ...cpuFields } = report;
      cpuQuote = cpuFields;
    }
    const gpuQuote =
      report.gpu ??
      (result.attestationType === "NVIDIA-GPU" ? report : null);
    const poc = report.proof_of_cloud;
    if (cpuQuote) {
      console.log("\nCPU quote:");
      console.log(JSON.stringify(cpuQuote, null, 2));
    }
    if (gpuQuote) {
      console.log("\nGPU quote:");
      console.log(JSON.stringify(gpuQuote, null, 2));
    }
    if (poc) {
      console.log("\nProof of cloud:");
      console.log(JSON.stringify(poc, null, 2));
    }
  }

  if (result.errors.length > 0) {
    console.log("\nErrors:");
    for (const err of result.errors) console.log(`  - ${err}`);
  }

  console.log(`\n${result.valid ? "✅ All Passed" : "🚫 Failed"}`);
  process.exit(result.valid ? 0 : 1);

} catch (err: any) {
  console.error(`Error: ${formatError(err)}`);
  process.exit(1);
}
