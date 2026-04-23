import { parseTdxQuoteFields } from "./tdx.js";
import { detectCpuQuoteType } from "./cpu.js";
import { isVmUrl, fetchCpuQuote, fetchDockerCompose } from "./url.js";
import {
    findMatchingArtifacts,
    pickNewestVersion,
    loadSevRegistry,
    type TdxArtifactEntry,
    type SevArtifactEntry,
} from "./artifacts.js";
import { calculateRtmr3 } from "./rtmr.js";
import { calcSevMeasurement, parseSevFamilyId, VCPU_MAP } from "./sevGctx.js";
import { createHash } from "node:crypto";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type WorkloadStatus =
    | "authentic_match"     // known SecretVM AND compose matches
    | "authentic_mismatch"  // known SecretVM but compose does NOT match
    | "not_authentic";      // mrtd/rtmr0..2 not in registry

export interface WorkloadResult {
    status: WorkloadStatus;
    /** Only set when status !== "not_authentic" */
    template_name?: string;
    vm_type?: string;
    artifacts_ver?: string;
    env?: string;
}

// ---------------------------------------------------------------------------
// Version resolution (no workload check)
// ---------------------------------------------------------------------------

/**
 * Given a TDX quote (hex string), look up the matching SecretVM version and
 * template.  Returns null when the quote is not from a known SecretVM.
 */
export async function resolveSecretVmVersion(
    quoteHexOrUrl: string,
): Promise<{ template_name: string; artifacts_ver: string } | null> {
    const quoteHex = isVmUrl(quoteHexOrUrl) ? await fetchCpuQuote(quoteHexOrUrl) : quoteHexOrUrl;
    const { mrtd, rtmr0, rtmr1, rtmr2 } = parseTdxQuoteFields(quoteHex);
    const matches = findMatchingArtifacts(mrtd, rtmr0, rtmr1, rtmr2);
    const newest = pickNewestVersion(matches);
    if (!newest) return null;
    return {
        template_name: newest.template_name,
        artifacts_ver: newest.artifacts_ver,
    };
}

/**
 * Given an AMD SEV-SNP attestation report (base64), look up the matching
 * SecretVM registry entry.  Returns null when not found.
 */
export async function resolveAmdSevVersion(
    quoteBase64OrUrl: string,
): Promise<{ template_name: string; vm_type: string; artifacts_ver: string } | null> {
    const quoteBase64 = isVmUrl(quoteBase64OrUrl) ? await fetchCpuQuote(quoteBase64OrUrl) : quoteBase64OrUrl;
    let raw: Buffer;
    try {
        raw = Buffer.from(quoteBase64.trim(), "base64");
    } catch {
        return null;
    }
    if (raw.length < 0x030) return null;
    const family = parseSevFamilyId(raw.subarray(0x010, 0x020));
    if (!family) return null;
    const imageId = raw.subarray(0x020, 0x030).toString("utf8").replace(/[\x00#]+$/, "");
    if (!imageId) return null;
    let registry: SevArtifactEntry[];
    try {
        registry = loadSevRegistry();
    } catch {
        return null;
    }
    const entry = registry.find(
        (e) => e.vm_type === family.vmType && e.artifacts_ver === imageId,
    );
    if (!entry) return null;
    return {
        template_name: family.templateName,
        vm_type: family.vmType,
        artifacts_ver: imageId,
    };
}

// ---------------------------------------------------------------------------
// Workload verification
// ---------------------------------------------------------------------------

/**
 * Verify that a TDX quote (hex) was produced by a known SecretVM running the
 * given docker-compose YAML.
 *
 * Steps:
 *  1. Parse mrtd + rtmr0..3 from the quote.
 *  2. Find all registry rows matching mrtd+rtmr0..2.
 *  3. If none → not_authentic.
 *  4. For each candidate row: calculate expected RTMR3 from the compose YAML
 *     and the row's rootfs_data, then compare to the quote's rtmr3.
 *  5. If any row matches → authentic_match.
 *  6. Otherwise → authentic_mismatch.
 */
export interface DockerFilesInput {
    /** Raw bytes of the docker-files tar archive. SHA-256 is computed client-side. */
    dockerFiles?: Uint8Array | Buffer;
    /** Precomputed SHA-256 hex digest of the docker-files archive. Takes precedence over dockerFiles. */
    dockerFilesSha256?: string;
}

export async function verifyTdxWorkload(
    quoteHexOrUrl: string,
    dockerComposeYaml?: string,
    dockerFilesInput?: DockerFilesInput,
): Promise<WorkloadResult> {
    let quoteHex: string;
    let compose: string;
    if (isVmUrl(quoteHexOrUrl)) {
        quoteHex = await fetchCpuQuote(quoteHexOrUrl);
        compose = dockerComposeYaml ?? await fetchDockerCompose(quoteHexOrUrl);
    } else {
        quoteHex = quoteHexOrUrl;
        if (!dockerComposeYaml) return { status: "not_authentic" };
        compose = dockerComposeYaml;
    }

    let dockerFilesSha256: string | undefined;
    if (dockerFilesInput?.dockerFilesSha256) {
        dockerFilesSha256 = dockerFilesInput.dockerFilesSha256;
    } else if (dockerFilesInput?.dockerFiles) {
        const bytes = Buffer.from(dockerFilesInput.dockerFiles);
        dockerFilesSha256 = createHash("sha256").update(bytes).digest("hex");
    }
    let mrtd: string, rtmr0: string, rtmr1: string, rtmr2: string, quoteRtmr3: string;
    try {
        const fields = parseTdxQuoteFields(quoteHex);
        mrtd = fields.mrtd;
        rtmr0 = fields.rtmr0;
        rtmr1 = fields.rtmr1;
        rtmr2 = fields.rtmr2;
        quoteRtmr3 = fields.rtmr3;
    } catch {
        return { status: "not_authentic" };
    }

    const candidates = findMatchingArtifacts(mrtd, rtmr0, rtmr1, rtmr2);

    if (candidates.length === 0) {
        return { status: "not_authentic" };
    }

    // Pick "best" entry for reporting (newest version)
    const best: TdxArtifactEntry = pickNewestVersion(candidates)!;
    const template_name = best.template_name;
    // vm_type column in CSV stores the environment (prod/dev)
    const env = best.vm_type;
    const artifacts_ver = best.artifacts_ver;

    // Check compose against every candidate entry (different rootfs_data or envs)
    for (const entry of candidates) {
        const expected = calculateRtmr3(compose, entry.rootfs_data, dockerFilesSha256);
        if (expected === quoteRtmr3) {
            return {
                status: "authentic_match",
                template_name: entry.template_name,
                vm_type: entry.vm_type,
                artifacts_ver: entry.artifacts_ver,
                env: entry.vm_type,
            };
        }
    }

    return {
        status: "authentic_mismatch",
        template_name,
        vm_type: best.vm_type,
        artifacts_ver,
        env,
    };
}

// ---------------------------------------------------------------------------
// Human-readable output
// ---------------------------------------------------------------------------

export function formatWorkloadResult(r: WorkloadResult, vmUrl?: string): string {
    if (r.status === "not_authentic") {
        return "🚫 Attestation doesn't belong to an authentic SecretVM";
    }

    const vmLine = `✅ Confirmed an authentic SecretVM, vm_type ${r.template_name}, artifacts ${r.artifacts_ver}, environment ${r.env}`;

    const source = vmUrl ? `the docker-compose.yaml specified at ${vmUrl}:29343/docker-compose` : "the specified docker-compose.yaml";

    if (r.status === "authentic_match") {
        return vmLine + `\n✅ Confirmed that the VM is running ${source}`;
    }

    // authentic_mismatch
    return vmLine + `\n🚫 Attestation does not match ${source}`;
}

// ---------------------------------------------------------------------------
// SEV-SNP workload verification
// ---------------------------------------------------------------------------

/**
 * Verify an AMD SEV-SNP workload against a docker-compose.yaml.
 *
 * Recomputes the SEV-SNP GCTX launch digest from the registry entry matching
 * the quote's `family_id` / `image_id` and the provided compose content, then
 * compares it against the measurement in the report.
 *
 * @param quoteBase64      Base64-encoded AMD SEV-SNP attestation report.
 * @param dockerComposeYaml  Contents of the docker-compose.yaml file.
 */
export async function verifySevWorkload(
    quoteBase64OrUrl: string,
    dockerComposeYaml?: string,
    dockerFilesInput?: DockerFilesInput,
): Promise<WorkloadResult> {
    let quoteBase64: string;
    let compose: string;
    if (isVmUrl(quoteBase64OrUrl)) {
        quoteBase64 = await fetchCpuQuote(quoteBase64OrUrl);
        compose = dockerComposeYaml ?? await fetchDockerCompose(quoteBase64OrUrl);
    } else {
        quoteBase64 = quoteBase64OrUrl;
        if (!dockerComposeYaml) return { status: "not_authentic" };
        compose = dockerComposeYaml;
    }

    // Resolve docker-files digest (see init-sev: appended to kernel cmdline as
    // `docker_additional_files_hash=<hex>`, which is hashed into the SEV-SNP
    // launch measurement via the GCTX hash page).
    let dockerFilesSha256: string | undefined;
    if (dockerFilesInput?.dockerFilesSha256) {
        dockerFilesSha256 = dockerFilesInput.dockerFilesSha256
            .toLowerCase().replace(/^0x/, "");
    } else if (dockerFilesInput?.dockerFiles) {
        const bytes = Buffer.from(dockerFilesInput.dockerFiles);
        dockerFilesSha256 = createHash("sha256").update(bytes).digest("hex");
    }
    let raw: Buffer;
    try {
        raw = Buffer.from(quoteBase64.trim(), "base64");
    } catch {
        return { status: "not_authentic" };
    }

    if (raw.length < 0x090 + 48) return { status: "not_authentic" };

    let quoteMeasurement: string;
    let family: ReturnType<typeof parseSevFamilyId>;
    let imageId: string;
    try {
        quoteMeasurement = raw.subarray(0x090, 0x090 + 48).toString("hex");
        family = parseSevFamilyId(raw.subarray(0x010, 0x020));
        imageId = raw.subarray(0x020, 0x030).toString("utf8").replace(/[\x00#]+$/, "");
    } catch {
        return { status: "not_authentic" };
    }

    let registry: SevArtifactEntry[];
    try {
        registry = loadSevRegistry();
    } catch {
        return { status: "not_authentic" };
    }

    // raw SHA256 — matches jeeves compute_file_hash() (no YAML normalization)
    const composeHash = createHash("sha256").update(compose, "utf8").digest("hex");

    if (!family) {
        // family_id not set — brute-force all registry entries and vcpu counts
        for (const entry of registry) {
            for (const [templateName, vcpus] of Object.entries(VCPU_MAP)) {
                const prefix = entry.cmdline_extra
                    ? `console=ttyS0 loglevel=7 ${entry.cmdline_extra}`
                    : `console=ttyS0 loglevel=7`;
                let cmdline = `${prefix} docker_compose_hash=${composeHash} rootfs_hash=${entry.rootfs_hash}`;
                if (dockerFilesSha256) cmdline += ` docker_additional_files_hash=${dockerFilesSha256}`;
                try {
                    if (calcSevMeasurement(entry, vcpus, cmdline) === quoteMeasurement) {
                        return {
                            status: "authentic_match",
                            template_name: templateName,
                            vm_type: entry.vm_type,
                            artifacts_ver: entry.artifacts_ver,
                            env: entry.vm_type,
                        };
                    }
                } catch { /* skip */ }
            }
        }
        return { status: "not_authentic" };
    }

    const { vmType, templateName, vcpus } = family;

    const candidates = registry.filter((e) => e.vm_type === vmType);
    const versionEntries = imageId ? candidates.filter((e) => e.artifacts_ver === imageId) : [];

    function tryEntry(entry: SevArtifactEntry): boolean {
        const prefix = entry.cmdline_extra
            ? `console=ttyS0 loglevel=7 ${entry.cmdline_extra}`
            : `console=ttyS0 loglevel=7`;
        let cmdline = `${prefix} docker_compose_hash=${composeHash} rootfs_hash=${entry.rootfs_hash}`;
        if (dockerFilesSha256) {
            cmdline += ` docker_additional_files_hash=${dockerFilesSha256}`;
        }
        try {
            return calcSevMeasurement(entry, vcpus, cmdline) === quoteMeasurement;
        } catch {
            return false;
        }
    }

    // Try version-specific entries first
    for (const entry of versionEntries) {
        if (tryEntry(entry)) {
            return {
                status: "authentic_match",
                template_name: templateName,
                vm_type: templateName,
                artifacts_ver: entry.artifacts_ver,
                env: vmType,
            };
        }
    }

    // Fallback: other entries for this vm_type
    for (const entry of candidates) {
        if (imageId && entry.artifacts_ver === imageId) continue; // already tried above
        if (tryEntry(entry)) {
            return {
                status: "authentic_match",
                template_name: templateName,
                vm_type: templateName,
                artifacts_ver: entry.artifacts_ver,
                env: vmType,
            };
        }
    }

    // No compose match. If the version is in the registry the VM is authentic
    // but the provided compose doesn't match the measurement.
    if (versionEntries.length > 0) {
        return {
            status: "authentic_mismatch",
            template_name: templateName,
            vm_type: templateName,
            artifacts_ver: imageId,
            env: vmType,
        };
    }
    return { status: "not_authentic" };
}

// ---------------------------------------------------------------------------
// Generic workload verifier (auto-detects TDX vs SEV-SNP)
// ---------------------------------------------------------------------------

/**
 * Verify that a CPU quote was produced by a known SecretVM running the given
 * docker-compose YAML.  Automatically detects whether the quote is an Intel
 * TDX (hex) or AMD SEV-SNP (base64) quote and delegates to the appropriate
 * lower-level function.
 *
 * @param quoteData       Hex-encoded TDX quote **or** base64-encoded SEV-SNP report.
 * @param dockerComposeYaml  Contents of the docker-compose.yaml file.
 */
export async function verifyWorkload(
    quoteDataOrUrl: string,
    dockerComposeYaml?: string,
    dockerFilesInput?: DockerFilesInput,
): Promise<WorkloadResult> {
    if (isVmUrl(quoteDataOrUrl)) {
        const quoteData = await fetchCpuQuote(quoteDataOrUrl);
        const compose = dockerComposeYaml ?? await fetchDockerCompose(quoteDataOrUrl);
        const type = detectCpuQuoteType(quoteData);
        if (type === "TDX") return verifyTdxWorkload(quoteData, compose, dockerFilesInput);
        if (type === "SEV-SNP") return verifySevWorkload(quoteData, compose, dockerFilesInput);
        return { status: "not_authentic" };
    }
    if (!dockerComposeYaml) return { status: "not_authentic" };
    const type = detectCpuQuoteType(quoteDataOrUrl);
    if (type === "TDX") return verifyTdxWorkload(quoteDataOrUrl, dockerComposeYaml, dockerFilesInput);
    if (type === "SEV-SNP") return verifySevWorkload(quoteDataOrUrl, dockerComposeYaml, dockerFilesInput);
    return { status: "not_authentic" };
}
