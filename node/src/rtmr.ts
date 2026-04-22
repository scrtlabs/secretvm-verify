import crypto from "node:crypto";

// Initial MR value: 48 zero bytes
const INIT_MR = Buffer.alloc(48).toString("hex");

function measureSha256(data: Buffer): Buffer {
    return crypto.createHash("sha256").update(data).digest();
}

function replayRtmr(history: string[]): string {
    if (history.length === 0) return INIT_MR;

    let mr = Buffer.alloc(48);

    for (const entry of history) {
        const entryBytes = Buffer.from(entry, "hex");
        let padded: Buffer;
        if (entryBytes.length < 48) {
            padded = Buffer.concat([entryBytes, Buffer.alloc(48 - entryBytes.length)]);
        } else {
            padded = entryBytes;
        }
        const h = crypto.createHash("sha384");
        h.update(Buffer.concat([mr, padded]));
        mr = h.digest().subarray(0, 48);
    }

    return mr.toString("hex");
}

/**
 * Calculate RTMR3 from a docker-compose file and (optionally) a docker-files
 * archive digest.
 *
 * Replay log order (matches the TDX initramfs in secret-vm-build's init-tdx):
 *   1. SHA-256 of docker-compose bytes    → log[0]
 *   2. rootfs_data (hex)                  → log[1]
 *   3. SHA-256 of docker-files archive    → log[2]  (only when provided)
 */
export function calculateRtmr3(
    dockerCompose: Buffer | string,
    rootfsData: string,
    dockerFilesSha256?: string,
): string {
    const log: string[] = [];

    // Hash raw bytes directly (no YAML normalization) — matches portal's Buffer path
    const composeBuffer =
        typeof dockerCompose === "string"
            ? Buffer.from(dockerCompose)
            : dockerCompose;

    log.push(measureSha256(composeBuffer).toString("hex"));
    log.push(rootfsData.toLowerCase().replace(/^0x/, ""));

    if (dockerFilesSha256) {
        log.push(dockerFilesSha256.toLowerCase().replace(/^0x/, ""));
    }

    return replayRtmr(log);
}
