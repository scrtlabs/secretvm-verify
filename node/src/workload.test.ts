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
} from "./workload.js";
import { checkTdxCpuAttestation } from "./tdx.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TEST_DATA = resolve(__dirname, "../../test-data");

const dockerQuote = readFileSync(`${TEST_DATA}/tdx_cpu_docker_check_quote.txt`, "utf8");
const dockerCompose = readFileSync(`${TEST_DATA}/tdx_cpu_docker_check_compose.yaml`, "utf8");

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
