import crypto from "node:crypto";

// Initial MR value: 48 zero bytes
const INIT_MR = Buffer.alloc(48).toString("hex");

function measureSha256(data: Buffer): Buffer {
    return crypto.createHash("sha256").update(data).digest();
}

// dstack event type for RTMR3 app events (see dstack cc-eventlog): a fixed
// non-TCG constant. Always little-endian on the measuring host (x86_64 TDX),
// so we serialize LE regardless of the verifier's own endianness.
const DSTACK_EVENT_TYPE = 0x08000001;

function hexToBuf(hex: string): Buffer {
    return Buffer.from(hex.toLowerCase().replace(/^0x/, ""), "hex");
}

// dstack-util event digest (mirrors eventlog::TdxEventLog::event_digest):
//   sha384( event_type.to_le_bytes() || ":" || event_name || ":" || payload )
// The 48-byte result is what gets extended into RTMR3, in place of the raw
// hash that attest-tool's `extendrt` extends directly.
function dstackEventDigest(event: string, payload: Buffer): string {
    const et = Buffer.alloc(4);
    et.writeUInt32LE(DSTACK_EVENT_TYPE);
    return crypto
        .createHash("sha384")
        .update(Buffer.concat([et, Buffer.from(":"), Buffer.from(event, "utf8"), Buffer.from(":"), payload]))
        .digest()
        .toString("hex");
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
 * archive digest. There are two replay schemes; which one a VM uses is decided
 * by its init (`KMS == "dstack"|"gramine"` ⇔ a non-empty dstack app-id):
 *
 * attest-tool path (no app-id — original SecretVM images):
 *   each event extends RTMR3 with the RAW hash bytes (padded to 48):
 *     1. SHA-256 of docker-compose bytes
 *     2. rootfs_data (hex)
 *     3. SHA-256 of docker-files archive   (only when provided)
 *
 * dstack-util path (app-id present — from the VM's /info `{"dstack_app_id":…}`):
 *   each event extends RTMR3 with a dstack event *digest* (not the raw hash),
 *   `sha384(LE32(0x08000001) || ":" || name || ":" || payload)`, in order:
 *     1. app-id           payload = app-id bytes
 *     2. compose-hash     payload = SHA-256 of docker-compose bytes
 *     3. os-image-hash    payload = rootfs_data bytes
 *     4. docker-files-hash payload = SHA-256 of docker-files archive (when provided)
 *
 * Both then accumulate `mr = SHA-384(mr || entry)` from 48 zero bytes.
 */
export function calculateRtmr3(
    dockerCompose: Buffer | string,
    rootfsData: string,
    dockerFilesSha256?: string,
    dstackAppId?: string,
): string {
    // Hash raw bytes directly (no YAML normalization) — matches portal's Buffer path
    const composeBuffer =
        typeof dockerCompose === "string" ? Buffer.from(dockerCompose) : dockerCompose;
    const composeSha256 = measureSha256(composeBuffer);
    const rootfsHex = rootfsData.toLowerCase().replace(/^0x/, "");
    const dfHex = dockerFilesSha256?.toLowerCase().replace(/^0x/, "");

    if (dstackAppId) {
        // dstack-util extends the per-event digest, not the raw hash.
        const log: string[] = [
            dstackEventDigest("app-id", hexToBuf(dstackAppId)),
            dstackEventDigest("compose-hash", composeSha256),
            dstackEventDigest("os-image-hash", hexToBuf(rootfsHex)),
        ];
        if (dfHex) log.push(dstackEventDigest("docker-files-hash", hexToBuf(dfHex)));
        return replayRtmr(log);
    }

    // attest-tool extends the raw hash (padded to 48 by replayRtmr).
    const log: string[] = [composeSha256.toString("hex"), rootfsHex];
    if (dfHex) log.push(dfHex);
    return replayRtmr(log);
}
