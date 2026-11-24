import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it, type TestContext } from "node:test";
import { checkNvidiaGpuAttestation, type NvidiaClaimsVersion } from "./nvidia.js";
import { checkSecretVmWithRuntime, type SecretVmRuntime } from "./vm.js";
import { makeResult } from "./types.js";

const fixture = JSON.parse(readFileSync(new URL("../../test-data/nvidia_claims.json", import.meta.url), "utf8"));
const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "secp384r1" });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test-key" };

function jwt(claims: Record<string, any>): string {
  const header = Buffer.from(JSON.stringify({ alg: "ES384", kid: "test-key" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const data = `${header}.${body}`;
  const signature = sign("sha384", Buffer.from(data), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `${data}.${signature.toString("base64url")}`;
}

function corrupt(token: string): string {
  const parts = token.split(".");
  const bytes = Buffer.from(parts[2], "base64url");
  bytes[0] ^= 1;
  return `${parts[0]}.${parts[1]}.${bytes.toString("base64url")}`;
}

function mockNras(t: TestContext, platform = fixture.platform, gpus: Record<string, any> = { "GPU-0": fixture.gpu }, tamper = "") {
  const signedGpus = Object.fromEntries(Object.entries(gpus).map(([id, claims]) => {
    const token = jwt(claims);
    return [id, tamper === id ? corrupt(token) : token];
  }));
  const platformToken = jwt(platform);
  const requests: any[] = [];
  t.mock.method(globalThis, "fetch", async (_url: any, init?: RequestInit) => {
    if (init?.method === "POST") {
      requests.push(JSON.parse(String(init.body)));
      return Response.json([["JWT", tamper === "platform" ? corrupt(platformToken) : platformToken], signedGpus]);
    }
    return Response.json({ keys: [jwk] });
  });
  return requests;
}

describe("NVIDIA full claims (offline, real ES384 signatures)", () => {
  it("preserves full nested claims, future fields and all existing summary aliases", async (t) => {
    const requests = mockNras(t);
    const result = await checkNvidiaGpuAttestation('{"arch":"BLACKWELL","claims_version":"3.0"}');
    assert.equal(result.valid, true);
    assert.equal(requests[0].claims_version, "4.0");
    assert.equal(requests[0].arch, "BLACKWELL");
    assert.deepEqual(result.report.claims, fixture.platform);
    const gpu = result.report.gpus["GPU-0"];
    assert.deepEqual(gpu.claims, fixture.gpu);
    assert.equal(gpu.vbios_version, fixture.gpu["x-nvidia-gpu-vbios-version"]);
    assert.equal(gpu.driver_version, fixture.gpu["x-nvidia-gpu-driver-version"]);
    assert.equal(gpu.measurements, "success");
    assert.equal(gpu.claims["x-nvidia-attester-claims"].FSP_UCODE_MIN_SVN, 5);
    assert.equal(gpu.claims["x-nvidia-gpu-driver-rim-cert-chain"], null);
  });

  for (const version of ["2.0", "3.0"] as const) {
    it(`supports explicit ${version} and does not invent missing opaque fields`, async (t) => {
      const gpu = structuredClone(fixture.gpu);
      delete gpu["x-nvidia-attester-claims"];
      delete gpu["x-nvidia-mismatch-opaque-data-records"];
      delete gpu["x-nvidia-gpu-claims-version"];
      const requests = mockNras(t, { ...fixture.platform, "x-nvidia-ver": version }, { "GPU-0": gpu });
      const result = await checkNvidiaGpuAttestation("{}", version);
      assert.equal(result.valid, true);
      assert.equal(requests[0].claims_version, version);
      assert.equal("x-nvidia-attester-claims" in result.report.gpus["GPU-0"].claims, false);
    });
  }

  it("keeps GPU identities and claims separate in a multi-GPU result", async (t) => {
    const second = { ...fixture.gpu, ueid: "second-device" };
    mockNras(t, fixture.platform, { "GPU-0": fixture.gpu, "GPU-1": second });
    const result = await checkNvidiaGpuAttestation("{}");
    assert.equal(result.valid, true);
    assert.deepEqual(result.report.gpus["GPU-0"].claims, fixture.gpu);
    assert.deepEqual(result.report.gpus["GPU-1"].claims, second);
  });

  for (const target of ["platform", "GPU-0"]) {
    it(`does not trust added claims with a tampered ${target} signature`, async (t) => {
      mockNras(t, fixture.platform, { "GPU-0": fixture.gpu }, target);
      const result = await checkNvidiaGpuAttestation("{}");
      assert.equal(result.valid, false);
      assert.equal(result.checks[target === "platform" ? "platform_jwt_signature" : "GPU-0_jwt_signature"], false);
    });
  }

  it("retains opaque mismatch diagnostics without turning a denial into success", async (t) => {
    const records = [{ id: 37, name: "FSP_UCODE_MIN_SVN", goldenType: "MIN_SVN", goldenValue: 5, runtimeType: "MIN_SVN", runtimeValue: 4 }];
    const gpu = { ...fixture.gpu, measres: "fail", "x-nvidia-attester-claims": { FSP_UCODE_MIN_SVN: 4 }, "x-nvidia-mismatch-opaque-data-records": records };
    mockNras(t, { ...fixture.platform, "x-nvidia-overall-att-result": false }, { "GPU-0": gpu });
    const result = await checkNvidiaGpuAttestation("{}");
    assert.equal(result.valid, false);
    assert.deepEqual(result.report.gpus["GPU-0"].claims["x-nvidia-mismatch-opaque-data-records"], records);
  });

  it("rejects unsupported claims versions before contacting NRAS", async (t) => {
    const fetch = t.mock.method(globalThis, "fetch", async () => { throw new Error("unexpected network"); });
    const result = await checkNvidiaGpuAttestation("{}", "5.0" as NvidiaClaimsVersion);
    assert.equal(result.valid, false);
    assert.match(result.errors[0], /Unsupported NVIDIA claims version/);
    assert.equal(fetch.mock.callCount(), 0);
  });

  it("forwards the version through VM verification and preserves the full GPU report", async () => {
    let requestedVersion: NvidiaClaimsVersion | undefined;
    const gpuReport = { claims: fixture.platform, gpus: { "GPU-0": { claims: fixture.gpu } } };
    const runtime: SecretVmRuntime = {
      fetch: (async (url: any) => Response.json(String(url).endsWith("/gpu") ? { nonce: "00" } : {})) as typeof fetch,
      getTlsCertBinding: async () => ({ spki: Buffer.alloc(32), certificate: Buffer.alloc(32) }),
      checkCpuAttestation: async () => makeResult("TDX", { report: { report_data: "00".repeat(64) } }),
      checkNvidiaGpuAttestation: async (_data, version) => {
        requestedVersion = version;
        return makeResult("NVIDIA-GPU", { valid: true, report: gpuReport });
      },
      verifyWorkload: async () => ({ status: "not_authentic" }),
    };
    const result = await checkSecretVmWithRuntime("https://example.test:29343", { gpuClaimsVersion: "3.0" }, runtime);
    assert.equal(requestedVersion, "3.0");
    assert.deepEqual(result.report.gpu, gpuReport);
  });
});
