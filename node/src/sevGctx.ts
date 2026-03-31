/**
 * SEV-SNP GCTX launch-digest computation.
 * Ported from sev-snp-measure (IBM, Apache-2.0).
 */

import { createHash, createHmac } from "node:crypto";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LD_SIZE = 48; // SHA-384 digest size
const ZEROS = Buffer.alloc(LD_SIZE);
const VMSA_GPA = BigInt("0xFFFFFFFFF000");

/** vcpu_sig for EPYC / EPYC-v1..v4:  amd_cpu_sig(family=23, model=1, stepping=2) */
export const VCPU_SIG_EPYC = 0x00800f12;
export const GUEST_FEATURES = 0x1;
export const BSP_EIP = 0xfffffff0;

export const VCPU_MAP: Record<string, number> = {
    small: 1,
    medium: 2,
    large: 4,
    "2xlarge": 8,
};

// ---------------------------------------------------------------------------
// SHA-384 helpers
// ---------------------------------------------------------------------------

function sha384(data: Buffer): Buffer {
    return createHash("sha384").update(data).digest() as unknown as Buffer;
}

// ---------------------------------------------------------------------------
// GCTX page-update primitive
// ---------------------------------------------------------------------------

function gctxUpdate(ld: Buffer, pageType: number, gpa: bigint, contents: Buffer): Buffer {
    // PAGE_INFO structure per AMD SNP spec §8.17.2 Table 67
    const buf = Buffer.allocUnsafe(0x70);
    ld.copy(buf, 0);           // current launch digest (48 bytes)
    contents.copy(buf, 48);    // page content hash (48 bytes)
    buf.writeUInt16LE(0x70, 96);   // page_info_len
    buf.writeUInt8(pageType, 98);  // page_type
    buf.writeUInt8(0, 99);         // is_imi
    buf.writeUInt8(0, 100);        // vmpl3_perms
    buf.writeUInt8(0, 101);        // vmpl2_perms
    buf.writeUInt8(0, 102);        // vmpl1_perms
    buf.writeUInt8(0, 103);        // reserved
    buf.writeBigUInt64LE(gpa, 104);
    return sha384(buf);
}

// ---------------------------------------------------------------------------
// Page-type update helpers
// ---------------------------------------------------------------------------

export function gctxUpdateNormalPages(ld: Buffer, startGpa: bigint, data: Buffer): Buffer {
    for (let offset = 0; offset < data.length; offset += 4096) {
        const page = data.subarray(offset, offset + 4096);
        ld = gctxUpdate(ld, 0x01, startGpa + BigInt(offset), sha384(page));
    }
    return ld;
}

export function gctxUpdateVmsaPage(ld: Buffer, data: Buffer): Buffer {
    return gctxUpdate(ld, 0x02, VMSA_GPA, sha384(data));
}

export function gctxUpdateZeroPages(ld: Buffer, gpa: bigint, size: number): Buffer {
    for (let offset = 0; offset < size; offset += 4096) {
        ld = gctxUpdate(ld, 0x03, gpa + BigInt(offset), ZEROS);
    }
    return ld;
}

export function gctxUpdateSecretsPage(ld: Buffer, gpa: bigint): Buffer {
    return gctxUpdate(ld, 0x05, gpa, ZEROS);
}

export function gctxUpdateCpuidPage(ld: Buffer, gpa: bigint): Buffer {
    return gctxUpdate(ld, 0x06, gpa, ZEROS);
}

// ---------------------------------------------------------------------------
// Kernel hashes page builder
// Mirrors QEMU's sev_hashes_page construction exactly.
// ---------------------------------------------------------------------------

const SEV_HASH_TABLE_HEADER_GUID = "9438d606-4f22-4cc9-b479-a793d411fd21";
const SEV_KERNEL_ENTRY_GUID = "4de79437-abd2-427f-b835-d5b172d2045b";
const SEV_INITRD_ENTRY_GUID = "44baf731-3a2f-4bd7-9af1-41e29169781d";
const SEV_CMDLINE_ENTRY_GUID = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a";

function uuidToLE(guid: string): Buffer {
    // UUID string → RFC4122 bytes → convert first three groups to LE
    const hex = guid.replace(/-/g, "");
    const bytes = Buffer.from(hex, "hex");
    // Swap bytes for little-endian encoding (groups 1, 2, 3)
    const le = Buffer.from(bytes);
    // group1: bytes 0-3 (4 bytes, swap)
    le[0] = bytes[3]!; le[1] = bytes[2]!; le[2] = bytes[1]!; le[3] = bytes[0]!;
    // group2: bytes 4-5 (2 bytes, swap)
    le[4] = bytes[5]!; le[5] = bytes[4]!;
    // group3: bytes 6-7 (2 bytes, swap)
    le[6] = bytes[7]!; le[7] = bytes[6]!;
    // groups 4+5 remain big-endian
    return le;
}

function sevHashTableEntry(guidStr: string, hash: Buffer): Buffer {
    // SevHashTableEntry: guid(16) + length(u16 LE) + hash(32) = 50 bytes
    const entry = Buffer.allocUnsafe(50);
    uuidToLE(guidStr).copy(entry, 0);
    entry.writeUInt16LE(50, 16);
    hash.copy(entry, 18);
    return entry;
}

export function buildHashesPage(
    kernelHashHex: string,
    initrdHashHex: string,
    append: string,
    offsetInPage: number,
): Buffer {
    const kernelHash = Buffer.from(kernelHashHex, "hex");
    const initrdHash = initrdHashHex
        ? Buffer.from(initrdHashHex, "hex")
        : Buffer.from(createHash("sha256").update(Buffer.alloc(0)).digest());
    const cmdlineBytes = append ? Buffer.from(append + "\0", "utf8") : Buffer.from("\0", "utf8");
    const cmdlineHash = Buffer.from(createHash("sha256").update(cmdlineBytes).digest());

    // SevHashTable: guid(16) + length(u16) + cmdline_entry(50) + initrd_entry(50) + kernel_entry(50) = 168 bytes
    const ht = Buffer.allocUnsafe(168);
    uuidToLE(SEV_HASH_TABLE_HEADER_GUID).copy(ht, 0);
    ht.writeUInt16LE(168, 16);
    sevHashTableEntry(SEV_CMDLINE_ENTRY_GUID, cmdlineHash).copy(ht, 18);
    sevHashTableEntry(SEV_INITRD_ENTRY_GUID, initrdHash).copy(ht, 68);
    sevHashTableEntry(SEV_KERNEL_ENTRY_GUID, kernelHash).copy(ht, 118);

    // Pad to 16-byte alignment: 168 % 16 = 8 → 8 padding bytes → 176 bytes total
    const padded = Buffer.concat([ht, Buffer.alloc(8)]);

    const page = Buffer.alloc(4096);
    padded.copy(page, offsetInPage);
    return page;
}

// ---------------------------------------------------------------------------
// VMSA page builder — QEMU SEV-SNP mode
// ---------------------------------------------------------------------------

export function buildVmsaPage(eip: number, vcpuSig: number, guestFeatures: bigint): Buffer {
    const page = Buffer.alloc(4096);

    function vmcbSeg(off: number, sel: number, attr: number, lim: number, base: bigint): void {
        page.writeUInt16LE(sel, off);
        page.writeUInt16LE(attr, off + 2);
        page.writeUInt32LE(lim, off + 4);
        page.writeBigUInt64LE(base, off + 8);
    }

    const csBase = BigInt((eip & 0xffff0000) >>> 0);
    const rip = BigInt(eip & 0x0000ffff);
    vmcbSeg(0x000, 0, 0x0093, 0xffff, 0n);         // es
    vmcbSeg(0x010, 0xf000, 0x009b, 0xffff, csBase);      // cs
    vmcbSeg(0x020, 0, 0x0093, 0xffff, 0n);          // ss
    vmcbSeg(0x030, 0, 0x0093, 0xffff, 0n);          // ds
    vmcbSeg(0x040, 0, 0x0093, 0xffff, 0n);          // fs
    vmcbSeg(0x050, 0, 0x0093, 0xffff, 0n);          // gs
    vmcbSeg(0x060, 0, 0x0000, 0xffff, 0n);          // gdtr
    vmcbSeg(0x070, 0, 0x0082, 0xffff, 0n);          // ldtr
    vmcbSeg(0x080, 0, 0x0000, 0xffff, 0n);          // idtr
    vmcbSeg(0x090, 0, 0x008b, 0xffff, 0n);          // tr
    page.writeBigUInt64LE(0x1000n, 0x0d0); // efer (SVME)
    page.writeBigUInt64LE(0x40n, 0x148); // cr4  (MCE)
    page.writeBigUInt64LE(0x10n, 0x158); // cr0  (PE)
    page.writeBigUInt64LE(0x400n, 0x160); // dr7
    page.writeBigUInt64LE(0xffff0ff0n, 0x168); // dr6
    page.writeBigUInt64LE(0x2n, 0x170); // rflags
    page.writeBigUInt64LE(rip, 0x178); // rip
    page.writeBigUInt64LE(0x0007040600070406n, 0x268); // g_pat
    page.writeBigUInt64LE(BigInt(vcpuSig), 0x310); // rdx (CPUID sig)
    page.writeBigUInt64LE(guestFeatures, 0x3b0); // sev_features
    page.writeBigUInt64LE(0x1n, 0x3e8); // xcr0
    page.writeUInt32LE(0x1f80, 0x408); // mxcsr
    page.writeUInt16LE(0x037f, 0x410); // x87_fcw
    return page;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export interface SevRegistryEntry {
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

export function calcSevMeasurement(entry: SevRegistryEntry, vcpus: number, cmdline: string): string {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let ld: any = Buffer.from(entry.ovmf_hash, "hex");

    const offsetInPage = entry.sev_hashes_table_gpa & 0xfff;
    const hashesPage = buildHashesPage(entry.kernel_hash, entry.initrd_hash, cmdline, offsetInPage);

    for (const sec of entry.ovmf_sections) {
        const gpa = BigInt(sec.gpa);
        switch (sec.section_type) {
            case 1:  // SNP_SEC_MEM
                ld = gctxUpdateZeroPages(ld, gpa, sec.size); break;
            case 2:  // SNP_SECRETS
                ld = gctxUpdateSecretsPage(ld, gpa); break;
            case 3:  // CPUID
                ld = gctxUpdateCpuidPage(ld, gpa); break;
            case 4:  // SVSM_CAA
                ld = gctxUpdateZeroPages(ld, gpa, sec.size); break;
            case 0x10: // SNP_KERNEL_HASHES
                ld = gctxUpdateNormalPages(ld, gpa, hashesPage); break;
        }
    }

    const apEip = entry.sev_es_reset_eip;
    for (let i = 0; i < vcpus; i++) {
        const eip = i === 0 ? BSP_EIP : apEip;
        const vmsa = buildVmsaPage(eip, VCPU_SIG_EPYC, BigInt(GUEST_FEATURES));
        ld = gctxUpdateVmsaPage(ld, vmsa);
    }

    return ld.toString("hex");
}

export function parseSevFamilyId(familyIdBytes: Buffer): { vmType: string; templateName: string; vcpus: number } | null {
    const s = familyIdBytes.subarray(0, 16).toString("utf8").replace(/[\x00#]+$/, "");
    if (!s.endsWith("-sev")) return null;
    const core = s.slice(0, -4); // strip "-sev"
    const idx = core.indexOf("-");
    if (idx < 0) return null;
    const vmType = core.slice(0, idx);
    const templateName = core.slice(idx + 1);
    const vcpus = VCPU_MAP[templateName];
    if (vcpus === undefined) return null;
    return { vmType, templateName, vcpus };
}
