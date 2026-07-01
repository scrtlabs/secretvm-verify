import { describe, it, mock, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

import {
  checkTdxCpuAttestation,
  checkSevCpuAttestation,
  checkNvidiaGpuAttestation,
  checkCpuAttestation,
  checkSecretVm,
  checkProofOfCloud,
  formatWorkloadResult,
} from "./index.js";
import type { AttestationResult } from "./types.js";
import { resetPeersCacheForTests } from "./proofOfCloud.js";
import { resolveAgentSecretVmEndpoints } from "./agent.js";
import { checkSecretVmWithRuntime, parseVmUrl, resolveSecretVmEndpoints } from "./vm.js";
import type { SecretVmRuntime } from "./vm.js";
import { calculateRtmr3 } from "./rtmr.js";
import { fetchDockerCompose, tlsCertSpkiSha256 } from "./url.js";

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

  it("rejects debug_allowed=true", async () => {
    // Policy is u64 at 0x008; bit 19 is DEBUG. Bit 19 lives in byte 0x00A,
    // bit 3 (0x08). Setting it forces debug_allowed=true.
    const raw = Buffer.from(
      loadFixture("amd_cpu_quote.txt").trim(),
      "base64",
    );
    const tampered = Buffer.from(raw);
    tampered[0x00a]! |= 0x08;
    const result = await checkSevCpuAttestation(
      tampered.toString("base64"),
      "Genoa",
    );
    if (skipIfRateLimited(result)) return;
    assert.equal(result.report.debug_allowed, true);
    assert.equal(result.checks.debug_disabled, false);
    assert.equal(result.valid, false);
  });

  it("rejects TCB ordering inversion", async () => {
    // Bump committed_tcb.snp above current_tcb.snp to break the
    // current >= committed invariant. committed_tcb is at 0x1E0; .snp is
    // at offset +6 in the 8-byte TcbVersion struct.
    const raw = Buffer.from(
      loadFixture("amd_cpu_quote.txt").trim(),
      "base64",
    );
    const tampered = Buffer.from(raw);
    tampered[0x1e0 + 6] = 0xff;
    const result = await checkSevCpuAttestation(
      tampered.toString("base64"),
      "Genoa",
    );
    if (skipIfRateLimited(result)) return;
    assert.equal(result.checks.tcb_ordering_valid, false);
    assert.equal(result.valid, false);
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

    it("preserves an explicitly declared default HTTPS port", () => {
      const { host, port } = parseVmUrl("https://myhost:443");
      assert.equal(host, "myhost");
      assert.equal(port, 443);
    });

    it("resolves separate attestation and TLS binding endpoints", () => {
      const endpoints = resolveSecretVmEndpoints(
        "https://myhost:29343",
        "https://myhost:21434",
      );
      assert.equal(endpoints.attestation.host, "myhost");
      assert.equal(endpoints.attestation.port, 29343);
      assert.equal(endpoints.attestation.baseUrl, "https://myhost:29343");
      assert.equal(endpoints.tls.host, "myhost");
      assert.equal(endpoints.tls.port, 21434);
      assert.equal(endpoints.tls.baseUrl, "https://myhost:21434");
    });

    it("preserves attestation path prefixes", () => {
      const endpoints = resolveSecretVmEndpoints(
        "https://attestation.example.com/teequote",
        "https://api.example.com",
      );
      assert.equal(endpoints.attestation.baseUrl, "https://attestation.example.com:29343/teequote");
      assert.equal(endpoints.tls.baseUrl, "https://api.example.com:443");
    });

    it("rejects concrete resource paths as attestation service URLs", async () => {
      for (const resource of ["cpu", "gpu", "docker-compose"]) {
        assert.throws(
          () => resolveSecretVmEndpoints(`https://attestation.example.com:29343/${resource}`),
          new RegExp(`concrete /${resource} resource path`),
        );
      }

      const result = await checkSecretVm("https://attestation.example.com:29343/cpu");
      assert.equal(result.valid, false);
      assert.match(result.errors[0] ?? "", /service base URL/);
    });

    it("fetches docker-compose as exact bytes without HTML dewrapping", async () => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (async (): Promise<Response> => {
        return new Response("<pre>services:\n  app: {}\n</pre>", { status: 200 });
      }) as typeof fetch;

      try {
        assert.equal(
          await fetchDockerCompose("attestation.example.com:29343"),
          "<pre>services:\n  app: {}\n</pre>",
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("requires an explicit single inference service for agent TLS binding", () => {
      const resolved = resolveAgentSecretVmEndpoints([
        { name: "teequote", endpoint: "agent.example.com" },
        { name: "status", endpoint: "status.example.com" },
        { name: "inference", endpoint: "agent.example.com" },
      ]);

      assert.equal(resolved.error, undefined);
      assert.equal(resolved.tlsBindingServiceName, "inference");
      assert.equal(resolved.endpoints?.attestation.baseUrl, "https://agent.example.com:29343");
      assert.equal(resolved.endpoints?.tls.baseUrl, "https://agent.example.com:443");
    });

    it("rejects agent metadata without an explicit inference service", () => {
      const resolved = resolveAgentSecretVmEndpoints([
        { name: "teequote", endpoint: "agent.example.com:29343" },
        { name: "status", endpoint: "api.example.com" },
      ]);

      assert.match(resolved.error ?? "", /No inference service endpoint/);
    });

    it("checks TLS on the service endpoint and fetches quotes from the attestation endpoint", async () => {
      const tlsHex = "11".repeat(32);
      const gpuNonce = "22".repeat(32);
      const cpuQuote = "cpu-quote";
      const gpuQuote = JSON.stringify({ nonce: gpuNonce, evidence_list: [] });
      const dockerCompose = "services:\n  app:\n    image: example/app@sha256:abc";
      const fetchedUrls: string[] = [];
      const tlsCalls: Array<{ host: string; port: number; servername?: string }> = [];
      const runtime: SecretVmRuntime = {
        fetch: (async (url: any): Promise<Response> => {
          const href = String(url);
          fetchedUrls.push(href);
          switch (href) {
            case "https://attest.example:29343/cpu":
              return new Response(cpuQuote);
            case "https://attest.example:29343/gpu":
              return new Response(gpuQuote);
            case "https://attest.example:29343/docker-compose":
              return new Response(dockerCompose);
            default:
              return new Response("unexpected endpoint", { status: 404 });
          }
        }) as typeof fetch,
        getTlsCertFingerprint: async (host, port, servername) => {
          tlsCalls.push({ host, port, servername });
          return Buffer.from(tlsHex, "hex");
        },
        checkCpuAttestation: async (data) => {
          assert.equal(data, cpuQuote);
          return {
            valid: true,
            attestationType: "TDX",
            checks: { quote_parsed: true, quote_verified: true },
            report: { report_data: tlsHex + gpuNonce },
            errors: [],
          };
        },
        checkNvidiaGpuAttestation: async (data) => {
          assert.equal(data, gpuQuote);
          return {
            valid: true,
            attestationType: "NVIDIA-GPU",
            checks: { gpu_attestation_verified: true },
            report: { overall_result: true },
            errors: [],
          };
        },
        verifyWorkload: async (data, compose) => {
          assert.equal(data, cpuQuote);
          assert.equal(compose, dockerCompose);
          return {
            status: "authentic_match",
            template_name: "prod-test",
            artifacts_ver: "v0.0.0",
          };
        },
      };

      const result = await checkSecretVmWithRuntime(
        "https://attest.example:29343",
        { tlsUrl: "https://api.example" },
        runtime,
      );

      assert.equal(result.valid, true);
      assert.deepEqual(tlsCalls, [
        { host: "api.example", port: 443, servername: "api.example" },
      ]);
      assert.deepEqual(fetchedUrls, [
        "https://attest.example:29343/cpu",
        "https://attest.example:29343/gpu",
        "https://attest.example:29343/docker-compose",
      ]);
      assert.equal(result.report.attestation_url, "https://attest.example:29343");
      assert.equal(result.report.tls_binding_url, "https://api.example:443");
      assert.equal(result.checks.tls_binding_verified, true);
      assert.equal(result.checks.gpu_quote_verified, true);
      assert.equal(result.checks.gpu_binding_verified, true);
      assert.equal(result.checks.workload_binding_verified, true);
    });

    it("passes exact docker-compose response bytes into workload verification", async () => {
      const tlsHex = "11".repeat(32);
      const gpuNonce = "22".repeat(32);
      const cpuQuote = "cpu-quote";
      const gpuQuote = JSON.stringify({ nonce: gpuNonce, evidence_list: [] });
      const htmlCompose = "<pre>services:\n  app: {}\n</pre>";
      const runtime: SecretVmRuntime = {
        fetch: (async (url: any): Promise<Response> => {
          switch (String(url)) {
            case "https://attest.example:29343/cpu":
              return new Response(cpuQuote);
            case "https://attest.example:29343/gpu":
              return new Response(gpuQuote);
            case "https://attest.example:29343/docker-compose":
              return new Response(htmlCompose);
            default:
              return new Response("unexpected endpoint", { status: 404 });
          }
        }) as typeof fetch,
        getTlsCertFingerprint: async () => Buffer.from(tlsHex, "hex"),
        checkCpuAttestation: async () => ({
          valid: true,
          attestationType: "TDX",
          checks: { quote_parsed: true, quote_verified: true },
          report: { report_data: tlsHex + gpuNonce },
          errors: [],
        }),
        checkNvidiaGpuAttestation: async () => ({
          valid: true,
          attestationType: "NVIDIA-GPU",
          checks: { gpu_attestation_verified: true },
          report: { overall_result: true },
          errors: [],
        }),
        verifyWorkload: async (_data, compose) => {
          assert.equal(compose, htmlCompose);
          return { status: "authentic_mismatch" };
        },
      };

      const result = await checkSecretVmWithRuntime(
        "https://attest.example:29343",
        { tlsUrl: "https://api.example" },
        runtime,
      );

      assert.equal(result.valid, false);
      assert.equal(result.report.docker_compose, htmlCompose);
      assert.match(result.errors.join("\n"), /Workload mismatch/);
    });

    it("fails closed when GPU evidence is unavailable", async () => {
      const tlsHex = "11".repeat(32);
      const cpuQuote = "cpu-quote";
      const runtime: SecretVmRuntime = {
        fetch: (async (url: any): Promise<Response> => {
          switch (String(url)) {
            case "https://attest.example:29343/cpu":
              return new Response(cpuQuote);
            case "https://attest.example:29343/gpu":
              return new Response(JSON.stringify({ error: "GPU attestation not available" }));
            case "https://attest.example:29343/docker-compose":
              return new Response("services:\n  app: {}\n");
            default:
              return new Response("unexpected endpoint", { status: 404 });
          }
        }) as typeof fetch,
        getTlsCertFingerprint: async () => Buffer.from(tlsHex, "hex"),
        checkCpuAttestation: async () => ({
          valid: true,
          attestationType: "TDX",
          checks: { quote_parsed: true, quote_verified: true },
          report: { report_data: tlsHex + "22".repeat(32) },
          errors: [],
        }),
        checkNvidiaGpuAttestation: async () => {
          throw new Error("GPU verifier should not run without fetched evidence");
        },
        verifyWorkload: async () => ({ status: "authentic_match" }),
      };

      const result = await checkSecretVmWithRuntime(
        "https://attest.example:29343",
        { tlsUrl: "https://api.example" },
        runtime,
      );

      assert.equal(result.valid, false);
      assert.equal(result.checks.gpu_quote_fetched, false);
      assert.equal(result.checks.gpu_quote_verified, false);
      assert.equal(result.checks.gpu_binding_verified, false);
      assert.match(result.errors.join("\n"), /GPU attestation not available/);
    });

    it("binds to the certificate SPKI, not the reissued leaf certificate DER", () => {
      const dir = mkdtempSync(join(tmpdir(), "secretvm-spki-"));
      try {
        const keyPath = join(dir, "key.pem");
        const cert1Path = join(dir, "cert1.pem");
        const cert2Path = join(dir, "cert2.pem");
        execFileSync("openssl", ["genrsa", "-out", keyPath, "2048"]);
        execFileSync("openssl", [
          "req",
          "-new",
          "-x509",
          "-key",
          keyPath,
          "-out",
          cert1Path,
          "-days",
          "1",
          "-subj",
          "/CN=secretvm.test",
          "-set_serial",
          "1",
        ]);
        execFileSync("openssl", [
          "req",
          "-new",
          "-x509",
          "-key",
          keyPath,
          "-out",
          cert2Path,
          "-days",
          "1",
          "-subj",
          "/CN=secretvm.test",
          "-set_serial",
          "2",
        ]);

        const cert1 = new X509Certificate(readFileSync(cert1Path));
        const cert2 = new X509Certificate(readFileSync(cert2Path));
        assert.notEqual(
          createHash("sha256").update(cert1.raw).digest("hex"),
          createHash("sha256").update(cert2.raw).digest("hex"),
        );
        assert.equal(
          tlsCertSpkiSha256(cert1).toString("hex"),
          tlsCertSpkiSha256(cert2).toString("hex"),
        );
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
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

  // The refresh-success path best-effort persists the fetched list to the
  // bundled file. Save & restore it so tests don't clobber the committed copy.
  const PEERS_FILE = join(__dirname, "..", "data", "trust_server_peers.txt");
  let bundledBackup = "";
  before(() => {
    bundledBackup = readFileSync(PEERS_FILE, "utf8");
  });
  after(() => {
    writeFileSync(PEERS_FILE, bundledBackup, "utf8");
  });

  // Bundled peers (node/data/trust_server_peers.txt):
  //   https://trust-server.scrtlabs.com
  //   https://trust-server.nillion.network
  //   https://trust-server.iex.ec
  const BUNDLED_FIRST = "https://trust-server.scrtlabs.com";
  const BUNDLED_SECOND = "https://trust-server.nillion.network";

  // A TDX quote is hex with version=4 (uint16LE@0) and tee_type=0x81 (uint32LE@4).
  // 0x0004 LE => "0400", reserved "0000", 0x00000081 LE => "81000000".
  const TDX_QUOTE = "0400000081000000" + "ab".repeat(16);

  // Build a valid SEV-SNP buffer: version=2 (uint32LE@0), sig_algo=1 (uint32LE@0x34),
  // length >= 0x38.
  function makeSevBase64(): string {
    const buf = Buffer.alloc(0x40, 0);
    buf.writeUInt32LE(2, 0); // version
    buf.writeUInt32LE(1, 0x34); // sig_algo
    return buf.toString("base64");
  }

  type Json = Record<string, unknown>;

  /**
   * Build a fetch mock that branches on URL/host:
   *   - raw.githubusercontent.com  => peers-list GET (newline text)
   *   - {origin}/check_quote       => peer POST (JSON answer)
   */
  function makeFetch(opts: {
    peersListText?: string | null; // null/undefined => refresh fails (non-200/error)
    peersListThrows?: boolean;
    peerHandler: (origin: string, body: Json) => Response | Promise<Response>;
  }): typeof fetch {
    return (async (url: any, init?: any): Promise<Response> => {
      const u = String(url);
      if (u.includes("raw.githubusercontent.com")) {
        if (opts.peersListThrows) throw new Error("refresh network error");
        if (opts.peersListText == null) {
          return new Response("not found", { status: 404 });
        }
        return new Response(opts.peersListText, { status: 200 });
      }
      // peer POST {origin}/check_quote
      const parsed = new URL(u);
      assert.equal(parsed.pathname, "/check_quote");
      const origin = parsed.origin;
      const body = JSON.parse(init?.body) as Json;
      return opts.peerHandler(origin, body);
    }) as unknown as typeof fetch;
  }

  function mockFetch(impl: typeof fetch): void {
    (globalThis as any).fetch = impl;
    resetPeersCacheForTests();
  }

  function restoreFetch(): void {
    (globalThis as any).fetch = originalFetch;
    resetPeersCacheForTests();
    // Undo any best-effort persist a refresh test wrote to the bundled file.
    writeFileSync(PEERS_FILE, bundledBackup, "utf8");
  }

  function jsonResponse(obj: Json, status = 200): Response {
    return new Response(JSON.stringify(obj), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }

  it("sends a TDX (hex) quote unchanged and passes on whitelisted", async () => {
    let sentQuote: unknown;
    mockFetch(
      makeFetch({
        peersListThrows: true, // force bundled fallback
        peerHandler: (_origin, body) => {
          sentQuote = body.quote;
          return jsonResponse({ whitelisted: true, machine_id: "mach-1" });
        },
      }),
    );
    try {
      const result = await checkProofOfCloud(TDX_QUOTE);
      assert.equal(result.valid, true);
      assert.equal(result.checks.proof_of_cloud_verified, true);
      assert.equal(sentQuote, TDX_QUOTE.toLowerCase());
      assert.equal(result.report.proof_of_cloud.whitelisted, true);
      assert.equal(result.report.proof_of_cloud.machine_id, "mach-1");
      assert.equal(result.report.proof_of_cloud.trust_server, BUNDLED_FIRST);
      assert.deepEqual(result.report.proof_of_cloud.peers_tried, [BUNDLED_FIRST]);
      assert.deepEqual(result.errors, []);
    } finally {
      restoreFetch();
    }
  });

  it("converts a SEV-SNP (base64) quote to lowercase hex before sending", async () => {
    const sevB64 = makeSevBase64();
    const expectedHex = Buffer.from(sevB64, "base64").toString("hex");
    let sentQuote: unknown;
    mockFetch(
      makeFetch({
        peersListThrows: true,
        peerHandler: (_origin, body) => {
          sentQuote = body.quote;
          return jsonResponse({ whitelisted: true, machine_id: "mach-sev" });
        },
      }),
    );
    try {
      const result = await checkProofOfCloud(sevB64);
      assert.equal(result.valid, true);
      assert.equal(sentQuote, expectedHex);
      assert.equal(sentQuote, (sentQuote as string).toLowerCase());
      assert.equal(result.report.proof_of_cloud.machine_id, "mach-sev");
    } finally {
      restoreFetch();
    }
  });

  it("fails over to the second peer when the first peer fails", async () => {
    mockFetch(
      makeFetch({
        peersListThrows: true,
        peerHandler: (origin) => {
          if (origin === BUNDLED_FIRST) {
            // 404 with HTML body (route not implemented) => not usable
            return new Response("<html>not found</html>", { status: 404 });
          }
          return jsonResponse({ whitelisted: true, machine_id: "mach-2" });
        },
      }),
    );
    try {
      const result = await checkProofOfCloud(TDX_QUOTE);
      assert.equal(result.valid, true);
      assert.equal(result.report.proof_of_cloud.trust_server, BUNDLED_SECOND);
      assert.deepEqual(result.report.proof_of_cloud.peers_tried, [
        BUNDLED_FIRST,
        BUNDLED_SECOND,
      ]);
    } finally {
      restoreFetch();
    }
  });

  it("fails when no peer returns a usable answer", async () => {
    mockFetch(
      makeFetch({
        peersListThrows: true,
        peerHandler: () => new Response("err", { status: 500 }),
      }),
    );
    try {
      const result = await checkProofOfCloud(TDX_QUOTE);
      assert.equal(result.valid, false);
      assert.equal(result.checks.proof_of_cloud_verified, false);
      assert.equal(result.report.proof_of_cloud.trust_server, null);
      assert.equal(result.report.proof_of_cloud.machine_id, null);
      assert.ok(result.report.proof_of_cloud.peers_tried.length >= 1);
      assert.ok(result.errors.length >= 1);
      assert.ok(result.errors.some((e) => e.includes("HTTP 500")));
    } finally {
      restoreFetch();
    }
  });

  it("fails when the peer reports whitelisted:false", async () => {
    mockFetch(
      makeFetch({
        peersListThrows: true,
        peerHandler: () =>
          jsonResponse({ whitelisted: false, machine_id: "mach-x" }),
      }),
    );
    try {
      const result = await checkProofOfCloud(TDX_QUOTE);
      assert.equal(result.valid, false);
      assert.equal(result.report.proof_of_cloud.whitelisted, false);
      assert.equal(result.report.proof_of_cloud.machine_id, "mach-x");
      assert.ok(
        result.errors.some(
          (e) => e.includes("mach-x") && e.includes("not whitelisted"),
        ),
      );
    } finally {
      restoreFetch();
    }
  });

  it("fails when the peer reports revoked:true and surfaces revoked_at", async () => {
    mockFetch(
      makeFetch({
        peersListThrows: true,
        peerHandler: () =>
          jsonResponse({
            whitelisted: false,
            machine_id: "mach-r",
            revoked: true,
            revoked_at: "2026-01-02T03:04:05Z",
          }),
      }),
    );
    try {
      const result = await checkProofOfCloud(TDX_QUOTE);
      assert.equal(result.valid, false);
      assert.equal(result.report.proof_of_cloud.revoked, true);
      assert.equal(
        result.report.proof_of_cloud.revoked_at,
        "2026-01-02T03:04:05Z",
      );
      assert.ok(
        result.errors.some(
          (e) => e.includes("mach-r") && e.includes("revoked"),
        ),
      );
    } finally {
      restoreFetch();
    }
  });

  it("uses the refreshed peers list when the GitHub fetch succeeds", async () => {
    const refreshedPeer = "https://refreshed-peer.example.com";
    let queriedOrigin: string | undefined;
    mockFetch(
      makeFetch({
        peersListText: `# comment\n${refreshedPeer}/\n`,
        peerHandler: (origin) => {
          queriedOrigin = origin;
          return jsonResponse({ whitelisted: true, machine_id: "mach-fresh" });
        },
      }),
    );
    try {
      const result = await checkProofOfCloud(TDX_QUOTE);
      assert.equal(result.valid, true);
      assert.equal(queriedOrigin, refreshedPeer);
      assert.equal(result.report.proof_of_cloud.trust_server, refreshedPeer);
      assert.deepEqual(result.report.proof_of_cloud.peers_tried, [refreshedPeer]);
    } finally {
      restoreFetch();
    }
  });

  it("falls back to the bundled list when the refresh fails", async () => {
    mockFetch(
      makeFetch({
        peersListText: null, // 404 => refresh fails
        peerHandler: () =>
          jsonResponse({ whitelisted: true, machine_id: "mach-bundled" }),
      }),
    );
    try {
      const result = await checkProofOfCloud(TDX_QUOTE);
      assert.equal(result.valid, true);
      assert.equal(result.report.proof_of_cloud.trust_server, BUNDLED_FIRST);
    } finally {
      restoreFetch();
    }
  });

  it("drops a non-https / malformed peer line without discarding the rest", async () => {
    const goodPeer = "https://good-peer.example.com";
    let queriedOrigin: string | undefined;
    mockFetch(
      makeFetch({
        peersListText:
          "not-a-url\nhttp://insecure-peer.example.com\n" + goodPeer + "\n",
        peerHandler: (origin) => {
          queriedOrigin = origin;
          return jsonResponse({ whitelisted: true, machine_id: "mach-good" });
        },
      }),
    );
    try {
      const result = await checkProofOfCloud(TDX_QUOTE);
      assert.equal(result.valid, true);
      assert.equal(queriedOrigin, goodPeer);
      assert.deepEqual(result.report.proof_of_cloud.peers_tried, [goodPeer]);
    } finally {
      restoreFetch();
    }
  });

  it("returns an encode error with no network call on truncatable input", async () => {
    let networkCalled = false;
    mockFetch(
      makeFetch({
        peersListThrows: true,
        peerHandler: () => {
          networkCalled = true;
          return jsonResponse({ whitelisted: true, machine_id: "x" });
        },
      }),
    );
    // Wrap to also detect the refresh GET being issued.
    const branching = (globalThis as any).fetch;
    (globalThis as any).fetch = (async (url: any, init?: any) => {
      networkCalled = true;
      return branching(url, init);
    }) as typeof fetch;
    try {
      const result = await checkProofOfCloud("0400000081000000zz");
      assert.equal(result.valid, false);
      assert.equal(result.checks.proof_of_cloud_verified, false);
      assert.equal(networkCalled, false);
      assert.deepEqual(result.report.proof_of_cloud.peers_tried, []);
      assert.equal(result.report.proof_of_cloud.trust_server, null);
      assert.ok(
        result.errors.some((e) => e.includes("Could not encode quote")),
      );
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

describe("formatWorkloadResult", () => {
  it("formats the docker-compose URL from the parsed attestation base URL", () => {
    const out = formatWorkloadResult(
      {
        status: "authentic_match",
        template_name: "small",
        artifacts_ver: "v0.0.0",
        env: "prod",
      },
      "https://my-vm:21434/teequote",
    );

    assert.match(out, /https:\/\/my-vm:21434\/teequote\/docker-compose/);
    assert.doesNotMatch(out, /:21434:29343\/docker-compose/);
  });
});
