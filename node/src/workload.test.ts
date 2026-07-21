import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import {
    resolveSecretVmVersion,
    verifyTdxWorkload,
    verifySevWorkload,
    verifyWorkload,
    extractDstackAppId,
} from "./workload.js";
import { calculateRtmr3 } from "./rtmr.js";
import { checkTdxCpuAttestation } from "./tdx.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DATA = resolve(__dirname, "../../test-data");

const dockerQuote = readFileSync(`${TEST_DATA}/tdx_cpu_docker_check_quote.txt`, "utf8");
const dockerCompose = readFileSync(`${TEST_DATA}/tdx_cpu_docker_check_compose.yaml`, "utf8");

// Reproduce the old attest-rest /docker-compose HTML wrapper: the file content
// is HTML-escaped inside a <pre> block with a trailing zero-width space. The
// verifier must extract this back to the original bytes to match the measurement.
function htmlWrapCompose(compose: string): string {
    const escaped = compose
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    return `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><pre>${escaped}&#8203;</pre></body></html>`;
}

// ---------------------------------------------------------------------------
// resolveSecretVmVersion
// ---------------------------------------------------------------------------

describe("resolveSecretVmVersion", () => {
    it("resolves version from docker check quote", async () => {
        const v = await resolveSecretVmVersion(dockerQuote);
        assert.ok(v !== null, "should find a matching version");
        assert.equal(v!.template_name, "small");
        assert.ok(v!.artifacts_ver.startsWith("v0.0."), "artifacts_ver should look like a semver");
    });

    it("returns null for a corrupted/unknown quote", async () => {
        // Use a recognized TDX quote structure but flip MRTD bytes so it won't
        // match any registry entry.
        const raw = Buffer.from(dockerQuote.trim(), "hex");
        const corrupted = Buffer.from(raw);
        // MRTD is at offset 48+136=184, length 48. Flip first byte.
        corrupted[184] ^= 0xff;
        const v = await resolveSecretVmVersion(corrupted.toString("hex"));
        assert.equal(v, null, "corrupted MRTD should yield null (not in registry)");
    });
});

// ---------------------------------------------------------------------------
// verifyTdxWorkload
// ---------------------------------------------------------------------------

describe("verifyTdxWorkload", () => {
    it("returns authentic_match for correct quote + compose", async () => {
        const r = await verifyTdxWorkload(dockerQuote, dockerCompose);
        assert.equal(r.status, "authentic_match");
        assert.equal(r.template_name, "small");
        assert.ok(r.artifacts_ver!.startsWith("v0.0."));
        assert.equal(r.env, "prod");
    });

    it("returns authentic_match for an HTML-wrapped compose (old attest-rest)", async () => {
        const r = await verifyTdxWorkload(dockerQuote, htmlWrapCompose(dockerCompose));
        assert.equal(r.status, "authentic_match");
        assert.equal(r.template_name, "small");
    });

    it("returns authentic_mismatch when compose is changed", async () => {
        const alteredCompose = dockerCompose + "\n# tampered";
        const r = await verifyTdxWorkload(dockerQuote, alteredCompose);
        assert.equal(r.status, "authentic_mismatch");
        // Version info is still resolved even on mismatch
        assert.ok(r.template_name, "template_name should be set on mismatch");
        assert.ok(r.artifacts_ver, "artifacts_ver should be set on mismatch");
    });

    it("returns not_authentic for a quote with unknown MRTD", async () => {
        const raw = Buffer.from(dockerQuote.trim(), "hex");
        const corrupted = Buffer.from(raw);
        // Flip the MRTD (offset 184, 48 bytes)
        corrupted[184] ^= 0xff;
        const r = await verifyTdxWorkload(corrupted.toString("hex"), dockerCompose);
        assert.equal(r.status, "not_authentic");
    });

    it("returns not_authentic for a completely garbled quote", async () => {
        const r = await verifyTdxWorkload("not-hex-at-all!!!", dockerCompose);
        assert.equal(r.status, "not_authentic");
    });
});

// ---------------------------------------------------------------------------
// dstack app-id (RTMR3 first event)
// ---------------------------------------------------------------------------

describe("calculateRtmr3 with dstack_app_id", () => {
    const compose = "version: '3'\nservices: {}\n";
    const rootfs = "ab".repeat(48);
    const appId = "E418296d0E99734599a4138774E6b85e058A64FE";

    it("the dstack (app-id) scheme differs from the attest-tool scheme", () => {
        const withId = calculateRtmr3(compose, rootfs, undefined, appId);
        const without = calculateRtmr3(compose, rootfs);
        assert.notEqual(withId, without);
    });

    it("empty / undefined app-id falls back to the attest-tool schema", () => {
        const without = calculateRtmr3(compose, rootfs);
        assert.equal(calculateRtmr3(compose, rootfs, undefined, ""), without);
        assert.equal(calculateRtmr3(compose, rootfs, undefined, undefined), without);
    });

    it("normalizes case and a 0x prefix", () => {
        const canonical = calculateRtmr3(compose, rootfs, undefined, appId);
        assert.equal(calculateRtmr3(compose, rootfs, undefined, "0x" + appId.toLowerCase()), canonical);
        assert.equal(calculateRtmr3(compose, rootfs, undefined, appId.toUpperCase()), canonical);
    });

    // Ground-truth vectors captured from real SecretVMs running small/v0.0.34.
    // The compose fixture's SHA-256 is the compose-hash event payload (77f748eb…);
    // rootfs is the os-image-hash payload; the app-id comes from /info. The
    // expected RTMR3 is the exact value in each machine's TDX quote.
    const dstackCompose = readFileSync(`${TEST_DATA}/dstack_docker_compose.yaml`, "utf8");

    it("reproduces the prod (beige-lobster) RTMR3 from the event log", () => {
        const rtmr3 = calculateRtmr3(
            dstackCompose,
            "6a441f52179d66d4b82d8113a99892b1287a01ded04b2f47019750f824071cc0",
            undefined,
            "6c4ed58ae19edcc3b90a7d7bd9087aee951d1ecc",
        );
        assert.equal(rtmr3, "bd88eccd83e76e65edc863ad771edd4d1bf388c5c655979774aa476dfedf611df4b05e78cb9dacbfe655dd0ed4a11313");
    });

    it("reproduces the dev (gray-tyrannosaurus) RTMR3 from the event log", () => {
        const rtmr3 = calculateRtmr3(
            dstackCompose,
            "b28b457b468cd058be0732208d2edc79e41f42fd4a0d25353aacacf016b6dc4e",
            undefined,
            "020e04828a82f7e5466c47279120e1a8d087848a",
        );
        assert.equal(rtmr3, "7f3c3d4872dcea04729f51573cd30787b02efda396b8264d87082b6f9c8716423738f0038aeecb3e98f2c439664bbc08");
    });
});

describe("extractDstackAppId", () => {
    it("returns the normalized app-id", () => {
        assert.equal(
            extractDstackAppId('{"dstack_app_id":"E418296d0E99734599a4138774E6b85e058A64FE"}'),
            "e418296d0e99734599a4138774e6b85e058a64fe",
        );
    });
    it("strips a 0x prefix and lowercases", () => {
        assert.equal(extractDstackAppId('{"dstack_app_id":"0xDEAD"}'), "dead");
    });
    it("returns '' for empty, missing, or non-JSON bodies", () => {
        assert.equal(extractDstackAppId('{"dstack_app_id":""}'), "");
        assert.equal(extractDstackAppId("{}"), "");
        assert.equal(extractDstackAppId("<html>not json</html>"), "");
    });
});

describe("verifyTdxWorkload with dstack_app_id", () => {
    it("a spurious app-id turns an otherwise-matching workload into a mismatch", async () => {
        // The bundled quote was measured under the old (no app-id) schema, so
        // supplying an app-id must break the RTMR3 match.
        const r = await verifyTdxWorkload(
            dockerQuote,
            dockerCompose,
            undefined,
            "E418296d0E99734599a4138774E6b85e058A64FE",
        );
        assert.equal(r.status, "authentic_mismatch");
    });

    it("an empty app-id keeps the old-schema match", async () => {
        const r = await verifyTdxWorkload(dockerQuote, dockerCompose, undefined, "");
        assert.equal(r.status, "authentic_match");
    });
});

// ---------------------------------------------------------------------------
// checkTdxCpuAttestation (quote crypto verification)
// ---------------------------------------------------------------------------

describe("checkTdxCpuAttestation – workload quote", () => {
    it("passes all crypto checks for the docker check quote", async () => {
        const result = await checkTdxCpuAttestation(dockerQuote);
        assert.equal(result.valid, true);
        assert.equal(result.checks["quote_parsed"], true);
        assert.equal(result.checks["quote_verified"], true);
        assert.deepEqual(result.errors, []);
    });

    it("fails quote_verified for a corrupted quote", async () => {
        const raw = Buffer.from(dockerQuote.trim(), "hex");
        const corrupted = Buffer.from(raw);
        // Flip a byte inside the ECDSA quote signature (offset 636)
        corrupted[636] ^= 0xff;
        const result = await checkTdxCpuAttestation(corrupted.toString("hex"));
        assert.equal(result.checks["quote_verified"], false);
        assert.equal(result.valid, false);
    });

    it("fails quote_parsed for invalid hex input", async () => {
        const result = await checkTdxCpuAttestation("not-valid-hex!!!");
        assert.equal(result.valid, false);
        assert.equal(result.checks["quote_parsed"], false);
    });

    it("fails quote_parsed for a truncated quote", async () => {
        const result = await checkTdxCpuAttestation("aa".repeat(100));
        assert.equal(result.valid, false);
        assert.equal(result.checks["quote_parsed"], false);
    });
});

// ---------------------------------------------------------------------------
// verifySevWorkload
// ---------------------------------------------------------------------------

describe("verifySevWorkload", () => {
    it("returns authentic_match for v0.0.25 prod small quote + correct compose", async () => {
        const r = await verifySevWorkload(amdDockerQuote, amdDockerCompose);
        assert.equal(r.status, "authentic_match");
        assert.equal(r.template_name, "small");
        assert.equal(r.artifacts_ver, "v0.0.25");
        assert.equal(r.env, "prod");
    });

    it("returns authentic_match for an HTML-wrapped compose (old attest-rest)", async () => {
        const r = await verifySevWorkload(amdDockerQuote, htmlWrapCompose(amdDockerCompose));
        assert.equal(r.status, "authentic_match");
        assert.equal(r.template_name, "small");
        assert.equal(r.artifacts_ver, "v0.0.25");
    });

    it("returns authentic_mismatch when compose is tampered", async () => {
        const r = await verifySevWorkload(amdDockerQuote, amdDockerCompose + "\n# tampered");
        assert.equal(r.status, "authentic_mismatch");
        assert.equal(r.template_name, "small");
        assert.equal(r.artifacts_ver, "v0.0.25");
        assert.equal(r.env, "prod");
    });

    it("returns authentic_mismatch for a corrupted measurement field", async () => {
        // Version (image_id) is still readable — VM is recognised as authentic
        // but the measurement can’t match any GCTX computation → authentic_mismatch.
        const raw = Buffer.from(amdDockerQuote.trim(), "base64");
        const corrupted = Buffer.from(raw);
        corrupted[0x090] ^= 0xff;
        const r = await verifySevWorkload(corrupted.toString("base64"), amdDockerCompose);
        assert.equal(r.status, "authentic_mismatch");
        assert.equal(r.artifacts_ver, "v0.0.25");
    });

    it("returns not_authentic for garbled input", async () => {
        const r = await verifySevWorkload("not-valid-base64!!!", dockerCompose);
        assert.equal(r.status, "not_authentic");
    });

    it("returns authentic_mismatch when quote version is in registry but compose does not match", async () => {
        // amd_cpu_quote.txt (v0.0.25 prod) is in the registry;
        // dockerCompose (TDX compose) doesn’t match its measurement.
        const r = await verifySevWorkload(amdQuote, dockerCompose);
        assert.equal(r.status, "authentic_mismatch");
        assert.equal(r.template_name, "small");
        assert.equal(r.artifacts_ver, "v0.0.25");
    });
});

// ---------------------------------------------------------------------------
// verifyWorkload (generic auto-detect)
// ---------------------------------------------------------------------------

const amdQuote = readFileSync(`${TEST_DATA}/amd_cpu_quote.txt`, "utf8");
const amdDockerQuote = readFileSync(`${TEST_DATA}/amd_cpu_docker_check_quote.txt`, "utf8");
const amdDockerCompose = readFileSync(`${TEST_DATA}/amd_cpu_docker_check_compose.yaml`, "utf8");

describe("verifyWorkload", () => {
    it("delegates to verifyTdxWorkload for a TDX quote (authentic_match)", async () => {
        const r = await verifyWorkload(dockerQuote, dockerCompose);
        assert.equal(r.status, "authentic_match");
        assert.equal(r.template_name, "small");
        assert.ok(r.artifacts_ver!.startsWith("v0.0."));
    });

    it("delegates to verifyTdxWorkload and returns authentic_mismatch on compose change", async () => {
        const r = await verifyWorkload(dockerQuote, dockerCompose + "\n# tampered");
        assert.equal(r.status, "authentic_mismatch");
    });

    it("returns not_authentic for TDX quote with unknown MRTD", async () => {
        const raw = Buffer.from(dockerQuote.trim(), "hex");
        const corrupted = Buffer.from(raw);
        corrupted[184] ^= 0xff;
        const r = await verifyWorkload(corrupted.toString("hex"), dockerCompose);
        assert.equal(r.status, "not_authentic");
    });

    it("delegates to verifySevWorkload for AMD SEV-SNP docker check quote (authentic_match)", async () => {
        const r = await verifyWorkload(amdDockerQuote, amdDockerCompose);
        assert.equal(r.status, "authentic_match");
        assert.equal(r.template_name, "small");
        assert.equal(r.artifacts_ver, "v0.0.25");
        assert.equal(r.env, "prod");
    });

    it("returns authentic_mismatch for SEV-SNP quote when version is in registry but compose does not match", async () => {
        // amd_cpu_quote.txt (v0.0.25 prod) is in the registry;
        // dockerCompose (TDX compose) doesn’t match its measurement.
        const r = await verifyWorkload(amdQuote, dockerCompose);
        assert.equal(r.status, "authentic_mismatch");
        assert.equal(r.template_name, "small");
        assert.equal(r.artifacts_ver, "v0.0.25");
    });

    it("returns not_authentic for completely garbled input", async () => {
        const r = await verifyWorkload("not-a-quote-at-all!!!", dockerCompose);
        assert.equal(r.status, "not_authentic");
    });
});
