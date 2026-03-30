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
    it("resolves version from docker check quote", () => {
        const v = resolveSecretVmVersion(dockerQuote);
        assert.ok(v !== null, "should find a matching version");
        assert.equal(v!.template_name, "small");
        assert.ok(v!.artifacts_ver.startsWith("v0.0."), "artifacts_ver should look like a semver");
    });

    it("returns null for a corrupted/unknown quote", () => {
        // Use a recognized TDX quote structure but flip MRTD bytes so it won't
        // match any registry entry.
        const raw = Buffer.from(dockerQuote.trim(), "hex");
        const corrupted = Buffer.from(raw);
        // MRTD is at offset 48+136=184, length 48. Flip first byte.
        corrupted[184] ^= 0xff;
        const v = resolveSecretVmVersion(corrupted.toString("hex"));
        assert.equal(v, null, "corrupted MRTD should yield null (not in registry)");
    });
});

// ---------------------------------------------------------------------------
// verifyTdxWorkload
// ---------------------------------------------------------------------------

describe("verifyTdxWorkload", () => {
    it("returns authentic_match for correct quote + compose", () => {
        const r = verifyTdxWorkload(dockerQuote, dockerCompose);
        assert.equal(r.status, "authentic_match");
        assert.equal(r.template_name, "small");
        assert.ok(r.artifacts_ver!.startsWith("v0.0."));
        assert.equal(r.env, "prod");
    });

    it("returns authentic_mismatch when compose is changed", () => {
        const alteredCompose = dockerCompose + "\n# tampered";
        const r = verifyTdxWorkload(dockerQuote, alteredCompose);
        assert.equal(r.status, "authentic_mismatch");
        // Version info is still resolved even on mismatch
        assert.ok(r.template_name, "template_name should be set on mismatch");
        assert.ok(r.artifacts_ver, "artifacts_ver should be set on mismatch");
    });

    it("returns not_authentic for a quote with unknown MRTD", () => {
        const raw = Buffer.from(dockerQuote.trim(), "hex");
        const corrupted = Buffer.from(raw);
        // Flip the MRTD (offset 184, 48 bytes)
        corrupted[184] ^= 0xff;
        const r = verifyTdxWorkload(corrupted.toString("hex"), dockerCompose);
        assert.equal(r.status, "not_authentic");
    });

    it("returns not_authentic for a completely garbled quote", () => {
        const r = verifyTdxWorkload("not-hex-at-all!!!", dockerCompose);
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
        assert.equal(result.checks["cert_chain_valid"], true);
        assert.equal(result.checks["qe_report_signature_valid"], true);
        assert.equal(result.checks["attestation_key_bound"], true);
        assert.equal(result.checks["quote_signature_valid"], true);
        assert.deepEqual(result.errors, []);
    });

    it("fails quote_signature_valid for a corrupted quote", async () => {
        const raw = Buffer.from(dockerQuote.trim(), "hex");
        const corrupted = Buffer.from(raw);
        // Flip a byte inside the ECDSA quote signature (offset 636)
        corrupted[636] ^= 0xff;
        const result = await checkTdxCpuAttestation(corrupted.toString("hex"));
        assert.equal(result.checks["quote_signature_valid"], false);
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
// verifySevWorkload (TODO stub)
// ---------------------------------------------------------------------------

describe("verifySevWorkload", () => {
    it("always returns not_authentic (TODO stub)", () => {
        const r = verifySevWorkload("any-base64-data", dockerCompose);
        assert.equal(r.status, "not_authentic");
    });
});

// ---------------------------------------------------------------------------
// verifyWorkload (generic auto-detect)
// ---------------------------------------------------------------------------

const amdQuote = readFileSync(`${TEST_DATA}/amd_cpu_quote.txt`, "utf8");

describe("verifyWorkload", () => {
    it("delegates to verifyTdxWorkload for a TDX quote (authentic_match)", () => {
        const r = verifyWorkload(dockerQuote, dockerCompose);
        assert.equal(r.status, "authentic_match");
        assert.equal(r.template_name, "small");
        assert.ok(r.artifacts_ver!.startsWith("v0.0."));
    });

    it("delegates to verifyTdxWorkload and returns authentic_mismatch on compose change", () => {
        const r = verifyWorkload(dockerQuote, dockerCompose + "\n# tampered");
        assert.equal(r.status, "authentic_mismatch");
    });

    it("returns not_authentic for TDX quote with unknown MRTD", () => {
        const raw = Buffer.from(dockerQuote.trim(), "hex");
        const corrupted = Buffer.from(raw);
        corrupted[184] ^= 0xff;
        const r = verifyWorkload(corrupted.toString("hex"), dockerCompose);
        assert.equal(r.status, "not_authentic");
    });

    it("delegates to verifySevWorkload for an AMD SEV-SNP quote (TODO → not_authentic)", () => {
        // SEV-SNP workload check is not yet implemented; generic dispatcher
        // must recognise and call verifySevWorkload (which returns not_authentic).
        const r = verifyWorkload(amdQuote, dockerCompose);
        assert.equal(r.status, "not_authentic");
    });

    it("returns not_authentic for completely garbled input", () => {
        const r = verifyWorkload("not-a-quote-at-all!!!", dockerCompose);
        assert.equal(r.status, "not_authentic");
    });
});
