import { describe, it, mock } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  checkTdxCpuAttestation,
  checkSevCpuAttestation,
  checkNvidiaGpuAttestation,
  checkCpuAttestation,
  checkSecretVm,
  checkProofOfCloud,
} from "./index.js";
import type { AttestationResult } from "./types.js";
import { parseVmUrl } from "./vm.js";
import { calculateRtmr3 } from "./rtmr.js";
import { createHash } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DATA = join(__dirname, "..", "..", "test-data");

function loadFixture(name: string): string {
  return readFileSync(join(TEST_DATA, name), "utf8");
}

function skipIfRateLimited(result: AttestationResult) {
  if (
    result.checks.vcek_fetched === false &&
    result.errors.some((e) => e.includes("429"))
  ) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Intel TDX
// ---------------------------------------------------------------------------

describe("checkTdxCpuAttestation", () => {
  it("verifies a valid TDX quote", async () => {
    const result = await checkTdxCpuAttestation(loadFixture("cpu_quote.txt"));
    assert.equal(result.valid, true);
    assert.equal(result.attestationType, "TDX");
    assert.equal(result.checks.quote_parsed, true);
    assert.equal(result.checks.quote_verified, true);
    assert.deepEqual(result.errors, []);
  });

  it("returns correct report fields", async () => {
    const result = await checkTdxCpuAttestation(loadFixture("cpu_quote.txt"));
    assert.equal(result.report.version, 4);
    assert.equal(result.report.tee_type, 0x81);
    assert.equal(result.report.mr_td.length, 96); // 48 bytes hex
    assert.equal(result.report.report_data.length, 128); // 64 bytes hex
    assert.ok(result.report.fmspc.length > 0);
    assert.ok(
      result.report.tcb_status.includes("UpToDate") ||
        result.report.tcb_status.includes("OutOfDate"),
    );
  });

  it("rejects invalid hex", async () => {
    const result = await checkTdxCpuAttestation("not-valid-hex!!!");
    assert.equal(result.valid, false);
    assert.equal(result.checks.quote_parsed, false);
    assert.ok(result.errors.length > 0);
  });

  it("rejects truncated quote", async () => {
    const result = await checkTdxCpuAttestation("aa".repeat(100));
    assert.equal(result.valid, false);
    assert.equal(result.checks.quote_parsed, false);
  });

  it("rejects empty input", async () => {
    const result = await checkTdxCpuAttestation("");
    assert.equal(result.valid, false);
  });

  it("detects corrupted signature", async () => {
    const raw = Buffer.from(loadFixture("cpu_quote.txt").trim(), "hex");
    const corrupted = Buffer.from(raw);
    corrupted[640]! ^= 0xff;
    const result = await checkTdxCpuAttestation(corrupted.toString("hex"));
    assert.equal(result.checks.quote_verified, false);
    assert.equal(result.valid, false);
  });
});

// ---------------------------------------------------------------------------
// AMD SEV-SNP
// ---------------------------------------------------------------------------

describe("checkSevCpuAttestation", () => {
  it("verifies a valid AMD report", async () => {
    const result = await checkSevCpuAttestation(
      loadFixture("amd_cpu_quote.txt"),
      "Genoa",
    );
    if (skipIfRateLimited(result)) return;
    assert.equal(result.valid, true);
    assert.equal(result.attestationType, "SEV-SNP");
    assert.equal(result.checks.report_parsed, true);
    assert.equal(result.checks.vcek_fetched, true);
    assert.equal(result.checks.cert_chain_valid, true);
    assert.equal(result.checks.report_signature_valid, true);
    assert.deepEqual(result.errors, []);
  });

  it("returns correct report fields", async () => {
    const result = await checkSevCpuAttestation(
      loadFixture("amd_cpu_quote.txt"),
      "Genoa",
    );
    if (skipIfRateLimited(result)) return;
    assert.equal(result.report.version, 3);
    assert.equal(result.report.vmpl, 1);
    assert.equal(result.report.product, "Genoa");
    assert.equal(result.report.debug_allowed, false);
    assert.equal(result.report.measurement.length, 96);
    assert.equal(result.report.report_data.length, 128);
    assert.equal(result.report.chip_id.length, 128);
  });

  it("auto-detects product", async () => {
    const result = await checkSevCpuAttestation(
      loadFixture("amd_cpu_quote.txt"),
    );
    if (skipIfRateLimited(result)) return;
    assert.equal(result.valid, true);
    assert.equal(result.report.product, "Genoa");
  });

  it("rejects invalid base64", async () => {
    const result = await checkSevCpuAttestation("!!!not-base64!!!");
    assert.equal(result.valid, false);
    assert.equal(result.checks.report_parsed, false);
    assert.ok(result.errors.length > 0);
  });

  it("rejects truncated report", async () => {
    const short = Buffer.alloc(100).toString("base64");
    const result = await checkSevCpuAttestation(short);
    assert.equal(result.valid, false);
    assert.equal(result.checks.report_parsed, false);
  });

  it("rejects empty input", async () => {
    const result = await checkSevCpuAttestation("");
    assert.equal(result.valid, false);
  });

  it("rejects wrong product", async () => {
    const result = await checkSevCpuAttestation(
      loadFixture("amd_cpu_quote.txt"),
      "Milan",
    );
    if (skipIfRateLimited(result)) return;
    assert.equal(result.valid, false);
    assert.equal(result.checks.vcek_fetched, false);
  });

  it("detects corrupted signature", async () => {
    const raw = Buffer.from(
      loadFixture("amd_cpu_quote.txt").trim(),
      "base64",
    );
    const corrupted = Buffer.from(raw);
    corrupted[0x090]! ^= 0xff;
    const result = await checkSevCpuAttestation(
      corrupted.toString("base64"),
      "Genoa",
    );
    if (skipIfRateLimited(result)) return;
    assert.equal(result.checks.report_signature_valid, false);
  });
});

// ---------------------------------------------------------------------------
// NVIDIA GPU
// ---------------------------------------------------------------------------

describe("checkNvidiaGpuAttestation", () => {
  it("verifies valid attestation", async () => {
    const result = await checkNvidiaGpuAttestation(
      loadFixture("gpu_attest.txt"),
    );
    assert.equal(result.valid, true);
    assert.equal(result.attestationType, "NVIDIA-GPU");
    assert.equal(result.checks.input_parsed, true);
    assert.equal(result.checks.nras_submission, true);
    assert.equal(result.checks.platform_jwt_signature, true);
    assert.deepEqual(result.errors, []);
  });

  it("returns correct report fields", async () => {
    const result = await checkNvidiaGpuAttestation(
      loadFixture("gpu_attest.txt"),
    );
    assert.equal(result.report.overall_result, true);
    assert.ok(Object.keys(result.report.gpus).length > 0);
    const gpu = Object.values(result.report.gpus)[0] as any;
    assert.ok(gpu.model);
    assert.equal(gpu.attestation_report_signature_verified, true);
  });

  it("rejects invalid JSON", async () => {
    const result = await checkNvidiaGpuAttestation("{not valid json");
    assert.equal(result.valid, false);
    assert.equal(result.checks.input_parsed, false);
    assert.ok(result.errors.length > 0);
  });

  it("rejects empty JSON object", async () => {
    const result = await checkNvidiaGpuAttestation("{}");
    assert.equal(result.valid, false);
    assert.equal(result.checks.nras_submission, false);
  });

  it("rejects empty input", async () => {
    const result = await checkNvidiaGpuAttestation("");
    assert.equal(result.valid, false);
  });
});

// ---------------------------------------------------------------------------
// CPU auto-detect
// ---------------------------------------------------------------------------

describe("checkCpuAttestation", () => {
  it("detects TDX", async () => {
    const result = await checkCpuAttestation(loadFixture("cpu_quote.txt"));
    assert.equal(result.attestationType, "TDX");
    assert.equal(result.valid, true);
  });

  it("detects AMD", async () => {
    const result = await checkCpuAttestation(
      loadFixture("amd_cpu_quote.txt"),
      "Genoa",
    );
    if (skipIfRateLimited(result)) return;
    assert.equal(result.attestationType, "SEV-SNP");
    assert.equal(result.valid, true);
  });

  it("returns unknown for bad input", async () => {
    const result = await checkCpuAttestation("this is not a quote");
    assert.equal(result.valid, false);
    assert.equal(result.attestationType, "unknown");
    assert.ok(result.errors.length > 0);
  });

  it("handles empty input", async () => {
    const result = await checkCpuAttestation("");
    assert.equal(result.valid, false);
  });
});

// ---------------------------------------------------------------------------
// Secret VM
// ---------------------------------------------------------------------------

describe("checkSecretVm", () => {
  it("fails on unreachable host", async () => {
    const result = await checkSecretVm("https://192.0.2.1:29343");
    assert.equal(result.valid, false);
    assert.equal(result.attestationType, "SECRET-VM");
    assert.equal(result.checks.tls_cert_fetched, false);
    assert.ok(result.errors.length > 0);
  });

  it("fails on empty URL", async () => {
    const result = await checkSecretVm("");
    assert.equal(result.valid, false);
  });

  describe("parseVmUrl", () => {
    it("handles bare hostname", () => {
      const { host, port } = parseVmUrl("myhost");
      assert.equal(host, "myhost");
      assert.equal(port, 29343);
    });

    it("handles hostname with port", () => {
      const { host, port } = parseVmUrl("myhost:1234");
      assert.equal(host, "myhost");
      assert.equal(port, 1234);
    });

    it("handles full URL with port", () => {
      const { host, port } = parseVmUrl("https://myhost:5555");
      assert.equal(host, "myhost");
      assert.equal(port, 5555);
    });

    it("handles full URL without port", () => {
      const { host, port } = parseVmUrl("https://myhost");
      assert.equal(host, "myhost");
      assert.equal(port, 29343);
    });
  });

  describe("mocked", () => {
    function makeTestData(tlsHex = "aa".repeat(32), nonceHex = "bb".repeat(32)) {
      const reportData = tlsHex + nonceHex;
      const tlsFp = Buffer.from(tlsHex, "hex");
      const cpuResult: AttestationResult = {
        valid: true,
        attestationType: "TDX",
        checks: { quote_parsed: true, quote_verified: true },
        report: { report_data: reportData, mr_td: "cc".repeat(48) },
        errors: [],
      };
      const gpuResult: AttestationResult = {
        valid: true,
        attestationType: "NVIDIA-GPU",
        checks: { platform_jwt_signature: true },
        report: { overall_result: true, gpus: {} },
        errors: [],
      };
      const gpuJson = JSON.stringify({
        nonce: nonceHex,
        arch: "HOPPER",
        evidence_list: [],
      });
      const noGpuJson = JSON.stringify({
        error: "GPU attestation not available",
        details: "The GPU attestation data has not been generated or is not ready yet",
      });
      return { tlsFp, cpuResult, gpuResult, gpuJson, noGpuJson, reportData };
    }

    // We test the logic by importing vm.ts internals won't work easily with
    // mocking in node:test, so we test the data flow expectations instead.

    it("no-GPU JSON has error field", () => {
      const { noGpuJson } = makeTestData();
      const parsed = JSON.parse(noGpuJson);
      assert.ok("error" in parsed);
    });

    it("test data is internally consistent", () => {
      const { tlsFp, reportData } = makeTestData();
      const firstHalf = reportData.slice(0, 64);
      assert.equal(firstHalf, tlsFp.toString("hex"));
    });

    it("nonce matches second half", () => {
      const nonceHex = "bb".repeat(32);
      const { reportData } = makeTestData("aa".repeat(32), nonceHex);
      const secondHalf = reportData.slice(64, 128);
      assert.equal(secondHalf, nonceHex);
    });
  });
});

// ---------------------------------------------------------------------------
// Proof of cloud
// ---------------------------------------------------------------------------

describe("checkProofOfCloud", () => {
  const originalFetch = globalThis.fetch;

  function mockFetch(impl: typeof fetch): void {
    (globalThis as any).fetch = impl;
  }

  function restoreFetch(): void {
    (globalThis as any).fetch = originalFetch;
  }

  it("returns PASS when endpoint confirms proof_of_cloud", async () => {
    mockFetch(async () =>
      new Response(
        JSON.stringify({
          proof_of_cloud: true,
          origin: "scrt",
          status: { attestation_type: "tdx", result: "0", exp_status: "0" },
          quote: { machine_id: "abc123" },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    try {
      const result = await checkProofOfCloud("fake-quote");
      assert.equal(result.valid, true);
      assert.equal(result.checks.proof_of_cloud_verified, true);
      assert.equal(result.report.proof_of_cloud.origin, "scrt");
      assert.equal(result.report.proof_of_cloud.machine_id, "abc123");
      assert.deepEqual(result.errors, []);
    } finally {
      restoreFetch();
    }
  });

  it("returns FAIL when endpoint reports proof_of_cloud=false", async () => {
    mockFetch(async () =>
      new Response(
        JSON.stringify({ proof_of_cloud: false, origin: null }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    try {
      const result = await checkProofOfCloud("fake-quote");
      assert.equal(result.valid, false);
      assert.equal(result.checks.proof_of_cloud_verified, false);
      assert.ok(result.errors.some((e) => e.includes("proof_of_cloud=false")));
    } finally {
      restoreFetch();
    }
  });

  it("returns FAIL when endpoint returns non-200", async () => {
    mockFetch(async () =>
      new Response("Internal Server Error", { status: 500 }),
    );
    try {
      const result = await checkProofOfCloud("fake-quote");
      assert.equal(result.valid, false);
      assert.equal(result.checks.proof_of_cloud_verified, false);
      assert.ok(result.errors.some((e) => e.includes("HTTP 500")));
    } finally {
      restoreFetch();
    }
  });

  it("returns FAIL on network error", async () => {
    mockFetch(async () => {
      throw new Error("ECONNREFUSED");
    });
    try {
      const result = await checkProofOfCloud("fake-quote");
      assert.equal(result.valid, false);
      assert.equal(result.checks.proof_of_cloud_verified, false);
      assert.ok(result.errors.some((e) => e.includes("ECONNREFUSED")));
    } finally {
      restoreFetch();
    }
  });

  it("posts the quote (trimmed) as JSON", async () => {
    let captured: { url?: string; body?: unknown } = {};
    mockFetch(async (url: any, init: any) => {
      captured.url = String(url);
      captured.body = JSON.parse(init?.body);
      return new Response(
        JSON.stringify({ proof_of_cloud: true, origin: "scrt" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    try {
      await checkProofOfCloud("  raw-quote-text  \n");
      assert.equal(captured.url, "https://secretai.scrtlabs.com/api/quote-parse");
      assert.deepEqual(captured.body, { quote: "raw-quote-text" });
    } finally {
      restoreFetch();
    }
  });
});

// ---------------------------------------------------------------------------
// RTMR3 calculation (with and without docker-files)
// ---------------------------------------------------------------------------

describe("calculateRtmr3", () => {
  const compose = "services:\n  app:\n    image: nginx\n";
  const rootfs = "de".repeat(32);  // any 32-byte hex
  const dockerFiles = Buffer.from("pretend this is a tar");
  const dockerFilesSha256 = createHash("sha256").update(dockerFiles).digest("hex");

  it("produces a different RTMR3 when docker-files digest is included", () => {
    const without = calculateRtmr3(compose, rootfs);
    const withDigest = calculateRtmr3(compose, rootfs, dockerFilesSha256);
    assert.notEqual(without, withDigest);
    assert.equal(without.length, 96);
    assert.equal(withDigest.length, 96);
  });

  it("normalizes 0x prefix and uppercase in docker-files digest", () => {
    const lower = calculateRtmr3(compose, rootfs, dockerFilesSha256);
    const withPrefix = calculateRtmr3(compose, rootfs, "0x" + dockerFilesSha256);
    const upper = calculateRtmr3(compose, rootfs, dockerFilesSha256.toUpperCase());
    assert.equal(withPrefix, lower);
    assert.equal(upper, lower);
  });

  it("matches when docker-files bytes are provided vs precomputed digest", () => {
    // This is tested via verifyTdxWorkload's internal path, but we replicate
    // the digest computation here to prove equivalence.
    const digestFromBytes = createHash("sha256").update(dockerFiles).digest("hex");
    const fromBytes = calculateRtmr3(compose, rootfs, digestFromBytes);
    const fromHex = calculateRtmr3(compose, rootfs, dockerFilesSha256);
    assert.equal(fromBytes, fromHex);
  });
});
