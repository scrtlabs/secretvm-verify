import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

export interface TdxArtifactEntry {
    template_name: string;
    vm_type: string;
    artifacts_ver: string;
    mrtd: string;
    rtmr0: string;
    rtmr1: string;
    rtmr2: string;
    rootfs_data: string;
    host_id: string;
}

function csvPath(): string {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    return join(__dirname, "..", "data", "tdx.csv");
}

function parseCsv(content: string): TdxArtifactEntry[] {
    const lines = content.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length < 2) return [];
    // skip header (lines[0])
    return lines.slice(1).map((line) => {
        const cols = line.split(",");
        return {
            template_name: cols[0]!.trim(),
            vm_type: cols[1]!.trim(),
            artifacts_ver: cols[2]!.trim(),
            mrtd: cols[3]!.trim().toLowerCase(),
            rtmr0: cols[4]!.trim().toLowerCase(),
            rtmr1: cols[5]!.trim().toLowerCase(),
            rtmr2: cols[6]!.trim().toLowerCase(),
            rootfs_data: cols[7]!.trim().toLowerCase(),
            host_id: cols[8]!.trim().toLowerCase(),
        };
    });
}

let _registry: TdxArtifactEntry[] | null = null;

export function loadTdxRegistry(): TdxArtifactEntry[] {
    if (_registry) return _registry;
    const content = readFileSync(csvPath(), "utf8");
    _registry = parseCsv(content);
    return _registry;
}

export function findMatchingArtifacts(
    mrtd: string,
    rtmr0: string,
    rtmr1: string,
    rtmr2: string,
): TdxArtifactEntry[] {
    const m = mrtd.toLowerCase().replace(/^0x/, "");
    const r0 = rtmr0.toLowerCase().replace(/^0x/, "");
    const r1 = rtmr1.toLowerCase().replace(/^0x/, "");
    const r2 = rtmr2.toLowerCase().replace(/^0x/, "");
    return loadTdxRegistry().filter(
        (e) =>
            e.mrtd === m &&
            e.rtmr0 === r0 &&
            e.rtmr1 === r1 &&
            e.rtmr2 === r2,
    );
}

// ---------------------------------------------------------------------------
// Semver-based version sorting (newest first)
// Pre-release (e.g. v0.0.25-beta.2) sorts BEFORE the release (v0.0.25)
// so release wins when we pick the "newest".
// ---------------------------------------------------------------------------

function parseSemver(ver: string): [number, number, number, string] {
    const clean = ver.replace(/^v/, "");
    const [corePart, pre = ""] = clean.split("-", 2);
    const parts = (corePart ?? "").split(".").map(Number);
    const major = parts[0] ?? 0;
    const minor = parts[1] ?? 0;
    const patch = parts[2] ?? 0;
    return [major, minor, patch, pre];
}

function compareVersions(a: string, b: string): number {
    const [aMaj, aMin, aPat, aPre] = parseSemver(a);
    const [bMaj, bMin, bPat, bPre] = parseSemver(b);
    if (aMaj !== bMaj) return bMaj - aMaj;
    if (aMin !== bMin) return bMin - aMin;
    if (aPat !== bPat) return bPat - aPat;
    // release ("") > pre-release (any non-empty string)
    if (aPre === "" && bPre !== "") return -1; // a is newer
    if (aPre !== "" && bPre === "") return 1;  // b is newer
    return bPre.localeCompare(aPre); // fallback: lexicographic
}

export function pickNewestVersion(
    entries: TdxArtifactEntry[],
): TdxArtifactEntry | null {
    if (!entries.length) return null;
    return entries.slice().sort((a, b) =>
        compareVersions(a.artifacts_ver, b.artifacts_ver),
    )[0]!;
}

export function resolveVersion(
    mrtd: string,
    rtmr0: string,
    rtmr1: string,
    rtmr2: string,
): { template_name: string; artifacts_ver: string } | null {
    const matches = findMatchingArtifacts(mrtd, rtmr0, rtmr1, rtmr2);
    const newest = pickNewestVersion(matches);
    if (!newest) return null;
    return {
        template_name: newest.template_name,
        artifacts_ver: newest.artifacts_ver,
    };
}

// ---------------------------------------------------------------------------
// SEV-SNP artifact registry
// ---------------------------------------------------------------------------

export interface SevArtifactEntry {
    vm_type: string;
    artifacts_ver: string;
    kernel_hash: string;
    initrd_hash: string;
    vcpu_type: string;
    rootfs_hash: string;
    ovmf_hash: string;
    sev_hashes_table_gpa: number;
    sev_es_reset_eip: number;
    ovmf_sections: Array<{ gpa: number; size: number; section_type: number }>;
}

function sevJsonPath(): string {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    return join(__dirname, "..", "data", "sev.json");
}

let _sevRegistry: SevArtifactEntry[] | null = null;

export function loadSevRegistry(): SevArtifactEntry[] {
    if (_sevRegistry) return _sevRegistry;
    const content = readFileSync(sevJsonPath(), "utf8");
    _sevRegistry = JSON.parse(content) as SevArtifactEntry[];
    return _sevRegistry;
}
