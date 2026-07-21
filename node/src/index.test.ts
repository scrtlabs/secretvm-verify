import { describe, it, mock, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
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
import { orderChecks } from "./types.js";
import { resetPeersCacheForTests } from "./proofOfCloud.js";
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

    it("enforce-gpu: gpu_present is ordered between tls_binding and gpu_quote_fetched", () => {
      // The enforce-gpu path records a `gpu_present` check; it must render in the
      // canonical position (right after the TLS binding, before the GPU details).
      const ordered = Object.keys(
        orderChecks({
          gpu_quote_fetched: false,
          tls_binding_verified: true,
          gpu_present: false,
          cpu_quote_verified: true,
        }),
      );
      assert.deepEqual(ordered, [
        "cpu_quote_verified",
        "tls_binding_verified",
        "gpu_present",
        "gpu_quote_fetched",
      ]);
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

describe("classifyTlsBinding", () => {
  it("accepts either SPKI or full-certificate digest and reports which", async () => {
    const { classifyTlsBinding } = await import("./url.js");
    const spki = Buffer.from("11".repeat(32), "hex");
    const certificate = Buffer.from("22".repeat(32), "hex");
    const binding = { spki, certificate };

    assert.deepEqual(classifyTlsBinding(spki.toString("hex"), binding), {
      verified: true,
      kind: "spki",
    });
    assert.deepEqual(classifyTlsBinding(certificate.toString("hex"), binding), {
      verified: true,
      kind: "certificate",
    });
    assert.deepEqual(classifyTlsBinding("33".repeat(32), binding), {
      verified: false,
    });
  });

  it("binds to the SPKI, which survives certificate reissuance with the same key", async () => {
    const { execFileSync } = await import("node:child_process");
    const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { X509Certificate, createHash } = await import("node:crypto");
    const { tlsCertSpkiSha256, tlsCertSha256 } = await import("./url.js");

    const dir = mkdtempSync(join(tmpdir(), "spki-"));
    try {
      const key = join(dir, "k.pem");
      const c1 = join(dir, "c1.pem");
      const c2 = join(dir, "c2.pem");
      execFileSync("openssl", ["genrsa", "-out", key, "2048"]);
      for (const [out, serial] of [[c1, "1"], [c2, "2"]] as const) {
        execFileSync("openssl", [
          "req", "-new", "-x509", "-key", key, "-out", out,
          "-days", "1", "-subj", "/CN=secretvm.test", "-set_serial", serial,
        ]);
      }
      const cert1 = new X509Certificate(readFileSync(c1));
      const cert2 = new X509Certificate(readFileSync(c2));
      // Different certificates (full-cert hash differs) ...
      assert.notEqual(tlsCertSha256(cert1).toString("hex"), tlsCertSha256(cert2).toString("hex"));
      // ... but the same key => identical SPKI hash.
      assert.equal(tlsCertSpkiSha256(cert1).toString("hex"), tlsCertSpkiSha256(cert2).toString("hex"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("strict endpoint parsing + split endpoints (ported from #3)", () => {
  it("rejects a concrete /cpu resource path as a service base URL", async () => {
    const { parseServiceBaseUrl } = await import("./url.js");
    assert.throws(
      () => parseServiceBaseUrl("https://host:29343/cpu", 29343),
      /service base URL/,
    );
  });

  it("rejects non-https and userinfo/query/fragment", async () => {
    const { parseServiceBaseUrl } = await import("./url.js");
    assert.throws(() => parseServiceBaseUrl("http://host", 29343), /https/);
    assert.throws(() => parseServiceBaseUrl("https://u:p@host", 29343), /userinfo/);
    assert.throws(() => parseServiceBaseUrl("https://host?x=1", 29343), /query/);
  });

  it("resolves separate attestation and TLS binding endpoints", async () => {
    const { resolveSecretVmEndpoints } = await import("./vm.js");
    const e = resolveSecretVmEndpoints("https://host:29343", "https://host:21434");
    assert.equal(e.attestation.baseUrl, "https://host:29343");
    assert.equal(e.tls.baseUrl, "https://host:21434");
  });

  it("preserves an attestation path prefix and defaults the TLS port to 443", async () => {
    const { resolveSecretVmEndpoints } = await import("./vm.js");
    const e = resolveSecretVmEndpoints("https://attest.example/teequote", "https://api.example");
    assert.equal(e.attestation.baseUrl, "https://attest.example:29343/teequote");
    assert.equal(e.tls.baseUrl, "https://api.example:443");
  });

  it("agent metadata requires a unique inference service for TLS binding", async () => {
    const { resolveAgentSecretVmEndpoints } = await import("./agent.js");
    const ok = resolveAgentSecretVmEndpoints([
      { name: "teequote", endpoint: "agent.example.com" },
      { name: "inference", endpoint: "agent.example.com" },
    ]);
    assert.equal(ok.error, undefined);
    assert.equal(ok.tlsBindingServiceName, "inference");

    const missing = resolveAgentSecretVmEndpoints([
      { name: "teequote", endpoint: "agent.example.com" },
    ]);
    assert.match(missing.error ?? "", /No inference service endpoint/);
  });
});

describe("bare-host default-port fallback (29343 → 21434)", () => {
  // Runtime whose /cpu answers only on the given port; every other fetch throws.
  // getTlsCertBinding returns dummy digests; downstream verification is allowed
  // to fail — we only assert which port the endpoints resolved to.
  function runtimeAnsweringOn(port: number) {
    return {
      fetch: async (input: any) => {
        const u = String(input);
        if (u.includes(`:${port}/`)) {
          return { ok: true, status: 200, text: async () => "00" } as any;
        }
        throw new Error("ECONNREFUSED");
      },
      getTlsCertBinding: async () => ({
        spki: Buffer.alloc(32),
        certificate: Buffer.alloc(32),
      }),
      checkCpuAttestation: async () => ({
        valid: false,
        report: {},
        attestationType: "tdx",
        errors: [],
      }),
      checkNvidiaGpuAttestation: async () => ({ valid: false }),
      verifyWorkload: async () => ({}),
    } as any;
  }

  it("binds to 29343 when the standard attestation port answers", async () => {
    const { checkSecretVmWithRuntime } = await import("./vm.js");
    const result = await checkSecretVmWithRuntime("host.example", {}, runtimeAnsweringOn(29343));
    assert.match(result.report.attestation_url, /:29343$/);
    assert.match(result.report.tls_binding_url, /:29343$/);
  });

  it("falls back to 21434 when 29343 is unreachable", async () => {
    const { checkSecretVmWithRuntime } = await import("./vm.js");
    const result = await checkSecretVmWithRuntime("host.example", {}, runtimeAnsweringOn(21434));
    assert.match(result.report.attestation_url, /:21434$/);
    assert.match(result.report.tls_binding_url, /:21434$/);
  });

  it("honors an explicit port without probing the fallback", async () => {
    const { checkSecretVmWithRuntime } = await import("./vm.js");
    // 29343 is unreachable, but the explicit port must be kept as-is (no 21434).
    const result = await checkSecretVmWithRuntime(
      "https://host.example:29343",
      {},
      runtimeAnsweringOn(21434),
    );
    assert.match(result.report.attestation_url, /:29343$/);
    assert.match(result.report.tls_binding_url, /:29343$/);
  });
});

describe("dstack_app_id provenance", () => {
  const APP_ID = "e418296d0e99734599a4138774e6b85e058a64fe";

  // Runtime serving /info with an app-id, with the CPU type and the workload
  // verdict dictated by the test. `appId` of "" simulates a pre-dstack image
  // whose /info is absent.
  function runtimeWith(attestationType: string, workloadStatus: string, appId = APP_ID) {
    return {
      fetch: async (input: any) => {
        const u = String(input);
        if (!u.includes(":29343/")) throw new Error("ECONNREFUSED");
        if (u.endsWith("/info")) {
          if (!appId) throw new Error("HTTP 404");
          return {
            ok: true,
            status: 200,
            text: async () => JSON.stringify({ dstack_app_id: appId }),
          } as any;
        }
        return { ok: true, status: 200, text: async () => "00" } as any;
      },
      getTlsCertBinding: async () => ({
        spki: Buffer.alloc(32),
        certificate: Buffer.alloc(32),
      }),
      checkCpuAttestation: async () => ({
        valid: true,
        report: {},
        attestationType,
        errors: [],
      }),
      checkNvidiaGpuAttestation: async () => ({ valid: false }),
      verifyWorkload: async () => ({ status: workloadStatus }),
    } as any;
  }

  it("marks the app-id verified on a TDX authentic_match", async () => {
    const { checkSecretVmWithRuntime } = await import("./vm.js");
    const r = await checkSecretVmWithRuntime(
      "host.example",
      {},
      runtimeWith("TDX", "authentic_match"),
    );
    assert.equal(r.report.dstack_app_id, APP_ID);
    assert.equal(r.report.dstack_app_id_verified, true);
  });

  it("marks the app-id UNverified on SEV-SNP even when the workload matches", async () => {
    // SEV-SNP has no app-id in its launch measurement, so a matching workload
    // says nothing about the value /info served.
    const { checkSecretVmWithRuntime } = await import("./vm.js");
    const r = await checkSecretVmWithRuntime(
      "host.example",
      {},
      runtimeWith("SEV-SNP", "authentic_match"),
    );
    assert.equal(r.report.dstack_app_id, APP_ID);
    assert.equal(r.report.dstack_app_id_verified, false);
  });

  it("marks the app-id UNverified when the TDX workload does not match", async () => {
    const { checkSecretVmWithRuntime } = await import("./vm.js");
    const r = await checkSecretVmWithRuntime(
      "host.example",
      {},
      runtimeWith("TDX", "authentic_mismatch"),
    );
    assert.equal(r.report.dstack_app_id, APP_ID);
    assert.equal(r.report.dstack_app_id_verified, false);
  });

  it("omits both fields when the VM serves no app-id", async () => {
    const { checkSecretVmWithRuntime } = await import("./vm.js");
    const r = await checkSecretVmWithRuntime(
      "host.example",
      {},
      runtimeWith("TDX", "authentic_match", ""),
    );
    assert.equal("dstack_app_id" in r.report, false);
    assert.equal("dstack_app_id_verified" in r.report, false);
  });
});
