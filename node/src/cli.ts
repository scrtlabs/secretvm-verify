#!/usr/bin/env node
import { checkSecretVm } from "./index.js";

const args = process.argv.slice(2);
const url = args.find((a) => !a.startsWith("--"));
const product = args.includes("--product")
  ? args[args.indexOf("--product") + 1] ?? ""
  : "";
const raw = args.includes("--raw");

if (!url) {
  console.log(`Usage: check-vm <url> [--product NAME] [--raw]`);
  console.log(`  e.g. check-vm https://my-vm:29343`);
  process.exit(1);
}

const result = await checkSecretVm(url, product);

if (raw) {
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.valid ? 0 : 1);
}

console.log(`Checking attestation for ${url} ...\n`);

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
if (report.cpu_type) console.log(`\nCPU type: ${report.cpu_type}`);
if (report.tls_fingerprint) console.log(`TLS fingerprint: ${report.tls_fingerprint}`);

const cpu = report.cpu ?? {};
if (cpu.report_data) console.log(`Report data: ${cpu.report_data}`);
if (cpu.measurement) console.log(`Measurement: ${cpu.measurement}`);
if (cpu.mr_td) console.log(`MR TD: ${cpu.mr_td}`);
if (cpu.tcb_status) console.log(`TCB status: ${cpu.tcb_status}`);
if (cpu.product) console.log(`AMD product: ${cpu.product}`);

const gpu = report.gpu ?? {};
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
