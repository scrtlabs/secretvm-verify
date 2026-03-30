import { parseTdxQuoteFields } from "./tdx.js";
import { detectCpuQuoteType } from "./cpu.js";
import {
    findMatchingArtifacts,
    pickNewestVersion,
    type TdxArtifactEntry,
} from "./artifacts.js";
import { calculateRtmr3 } from "./rtmr.js";

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
export function resolveSecretVmVersion(
    quoteHex: string,
): { template_name: string; artifacts_ver: string } | null {
    const { mrtd, rtmr0, rtmr1, rtmr2 } = parseTdxQuoteFields(quoteHex);
    const matches = findMatchingArtifacts(mrtd, rtmr0, rtmr1, rtmr2);
    const newest = pickNewestVersion(matches);
    if (!newest) return null;
    return {
        template_name: newest.template_name,
        artifacts_ver: newest.artifacts_ver,
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
export function verifyTdxWorkload(
    quoteHex: string,
    dockerComposeYaml: string,
): WorkloadResult {
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
        const expected = calculateRtmr3(dockerComposeYaml, entry.rootfs_data);
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

export function formatWorkloadResult(r: WorkloadResult): string {
    if (r.status === "not_authentic") {
        return "🚫 Attestation doesn't belong to an authentic SecretVM";
    }

    const vmLine = `✅ Confirmed an authentic SecretVM (TDX), vm_type ${r.template_name}, artifacts ${r.artifacts_ver}, environment ${r.env}`;

    if (r.status === "authentic_match") {
        return (
            vmLine +
            "\n✅ Confirmed that the VM is running the specified docker-compose.yaml"
        );
    }

    // authentic_mismatch
    return (
        vmLine +
        "\n🚫 Attestation does not match the specified docker-compose.yaml"
    );
}

// ---------------------------------------------------------------------------
// SEV-SNP workload verification (TODO)
// ---------------------------------------------------------------------------

/**
 * Verify an AMD SEV-SNP workload against a docker-compose.yaml.
 *
 * TODO: SEV-SNP workload verification is not yet implemented.
 * Always returns `not_authentic` until a SEV artifact registry and RTMR-
 * equivalent measurement replay logic are added.
 */
export function verifySevWorkload(
    _quoteBase64: string,
    _dockerComposeYaml: string,
): WorkloadResult {
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
export function verifyWorkload(
    quoteData: string,
    dockerComposeYaml: string,
): WorkloadResult {
    const type = detectCpuQuoteType(quoteData);
    if (type === "TDX") return verifyTdxWorkload(quoteData, dockerComposeYaml);
    if (type === "SEV-SNP") return verifySevWorkload(quoteData, dockerComposeYaml);
    return { status: "not_authentic" };
}
