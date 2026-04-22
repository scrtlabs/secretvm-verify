"""SecretVM workload verification (TDX and SEV-SNP)."""

import base64
import csv
import hashlib
import json
import struct
import uuid
from pathlib import Path
from typing import Optional

import yaml as _yaml

from .types import WorkloadResult
from .tdx import _tdx_parse_quote
from .cpu import _detect_cpu_quote_type


# ---------------------------------------------------------------------------
# RTMR replay
# ---------------------------------------------------------------------------

def _replay_rtmr(history: list) -> str:
    """SHA-384 RTMR accumulator -- mirrors portal's replayRTMR logic."""
    if not history:
        return "00" * 48

    mr = bytearray(48)
    for entry in history:
        entry_bytes = bytes.fromhex(entry)
        if len(entry_bytes) < 48:
            entry_bytes = entry_bytes + bytes(48 - len(entry_bytes))
        combined = bytes(mr) + entry_bytes
        digest = hashlib.sha384(combined).digest()
        mr = bytearray(digest[:48])

    return bytes(mr).hex()


def _calculate_rtmr3(
    docker_compose: str | bytes,
    rootfs_data: str,
    docker_files_sha256: Optional[str] = None,
) -> str:
    """Calculate expected RTMR3 from docker-compose, rootfs_data, and
    (optionally) a docker-files archive digest.

    Replay log order (matches the TDX initramfs in secret-vm-build):
      1. SHA-256 of docker-compose bytes
      2. rootfs_data (hex)
      3. SHA-256 of docker-files archive  (only when provided)
    """
    compose_bytes = docker_compose if isinstance(docker_compose, bytes) else docker_compose.encode("utf-8")
    sha256_hex = hashlib.sha256(compose_bytes).hexdigest()
    rootfs_hex = rootfs_data.lower().removeprefix("0x")
    log = [sha256_hex, rootfs_hex]
    if docker_files_sha256:
        log.append(docker_files_sha256.lower().removeprefix("0x"))
    return _replay_rtmr(log)


# ---------------------------------------------------------------------------
# Registry loader
# ---------------------------------------------------------------------------

_tdx_registry_cache: Optional[list] = None


def _load_tdx_registry() -> list:
    global _tdx_registry_cache
    if _tdx_registry_cache is not None:
        return _tdx_registry_cache

    csv_path = Path(__file__).parent / "data" / "tdx.csv"
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({k: v.strip().lower() for k, v in row.items()})
    _tdx_registry_cache = rows
    return rows


def _find_matching_artifacts(mrtd: str, rtmr0: str, rtmr1: str, rtmr2: str) -> list:
    m = mrtd.lower().removeprefix("0x")
    r0 = rtmr0.lower().removeprefix("0x")
    r1 = rtmr1.lower().removeprefix("0x")
    r2 = rtmr2.lower().removeprefix("0x")
    return [
        e for e in _load_tdx_registry()
        if e["mrtd"] == m and e["rtmr0"] == r0 and e["rtmr1"] == r1 and e["rtmr2"] == r2
    ]


def _parse_semver(ver: str):
    """Return (major, minor, patch, pre) tuple for sorting."""
    clean = ver.lstrip("v")
    dash = clean.find("-")
    if dash >= 0:
        core, pre = clean[:dash], clean[dash + 1:]
    else:
        core, pre = clean, ""
    parts = core.split(".")
    try:
        major, minor, patch = int(parts[0] or 0), int(parts[1] if len(parts) > 1 else 0), int(parts[2] if len(parts) > 2 else 0)
    except ValueError:
        major, minor, patch = 0, 0, 0
    return major, minor, patch, pre


def _pick_newest_version(entries: list) -> Optional[dict]:
    if not entries:
        return None

    def sort_key(e):
        major, minor, patch, pre = _parse_semver(e.get("artifacts_ver", ""))
        # release ("") beats pre-release; negate numeric parts for descending sort
        return (-major, -minor, -patch, 0 if pre == "" else 1, pre)

    return sorted(entries, key=sort_key)[0]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_secretvm_version(data_or_url: str) -> Optional[dict]:
    """Given a TDX quote (hex string) or VM URL, return matching SecretVM version info.

    Returns a dict with ``template_name`` and ``artifacts_ver``, or ``None``
    when the quote is not from a known SecretVM.
    """
    from .url import is_vm_url, fetch_cpu_quote
    data = fetch_cpu_quote(data_or_url) if is_vm_url(data_or_url) else data_or_url
    try:
        raw = bytes.fromhex(data.strip())
        q = _tdx_parse_quote(raw)
        td = q["td"]
        mrtd = td["mr_td"].hex()
        rtmr0 = td["rt_mr0"].hex()
        rtmr1 = td["rt_mr1"].hex()
        rtmr2 = td["rt_mr2"].hex()
    except Exception:
        return None

    matches = _find_matching_artifacts(mrtd, rtmr0, rtmr1, rtmr2)
    best = _pick_newest_version(matches)
    if best is None:
        return None
    return {
        "template_name": best["template_name"],
        "artifacts_ver": best["artifacts_ver"],
    }


def verify_tdx_workload(
    data_or_url: str,
    docker_compose_yaml: str = "",
    docker_files: Optional[bytes] = None,
    docker_files_sha256: Optional[str] = None,
) -> WorkloadResult:
    """Verify that a TDX quote was produced by a known SecretVM running the
    given docker-compose YAML.

    Args:
        data_or_url: Hex-encoded TDX quote, or a VM URL to fetch quote and compose from.
        docker_compose_yaml: Contents of the docker-compose.yaml file. Auto-fetched if URL.
        docker_files: Optional raw bytes of the docker-files tar archive. SHA-256 is
            computed client-side and appended to the RTMR3 replay. Ignored if
            docker_files_sha256 is also provided.
        docker_files_sha256: Optional hex SHA-256 digest of the docker-files archive.
            Takes precedence over docker_files.

    Returns:
        WorkloadResult with status "authentic_match", "authentic_mismatch", or
        "not_authentic".
    """
    from .url import is_vm_url, fetch_cpu_quote, fetch_docker_compose
    if is_vm_url(data_or_url):
        data = fetch_cpu_quote(data_or_url)
        docker_compose_yaml = docker_compose_yaml or fetch_docker_compose(data_or_url)
    else:
        data = data_or_url
        if not docker_compose_yaml:
            return WorkloadResult(status="not_authentic")

    # Resolve the docker-files digest: prefer explicit hex, fall back to
    # hashing the provided archive bytes.
    if docker_files_sha256:
        df_sha = docker_files_sha256
    elif docker_files is not None:
        df_sha = hashlib.sha256(docker_files).hexdigest()
    else:
        df_sha = None
    try:
        raw = bytes.fromhex(data.strip())
        q = _tdx_parse_quote(raw)
        td = q["td"]
        mrtd = td["mr_td"].hex()
        rtmr0 = td["rt_mr0"].hex()
        rtmr1 = td["rt_mr1"].hex()
        rtmr2 = td["rt_mr2"].hex()
        quote_rtmr3 = td["rt_mr3"].hex()
    except Exception:
        return WorkloadResult(status="not_authentic")

    candidates = _find_matching_artifacts(mrtd, rtmr0, rtmr1, rtmr2)
    if not candidates:
        return WorkloadResult(status="not_authentic")

    best = _pick_newest_version(candidates)
    template_name = best["template_name"]
    vm_type = best["vm_type"]
    artifacts_ver = best["artifacts_ver"]
    # vm_type column in CSV contains the environment (prod/dev)
    env = vm_type

    for entry in candidates:
        expected = _calculate_rtmr3(docker_compose_yaml, entry["rootfs_data"], df_sha)
        if expected == quote_rtmr3:
            return WorkloadResult(
                status="authentic_match",
                template_name=entry["template_name"],
                vm_type=entry["vm_type"],
                artifacts_ver=entry["artifacts_ver"],
                env=entry["vm_type"],
            )

    return WorkloadResult(
        status="authentic_mismatch",
        template_name=template_name,
        vm_type=vm_type,
        artifacts_ver=artifacts_ver,
        env=env,
    )


def format_workload_result(r: WorkloadResult) -> str:
    """Human-readable string for a WorkloadResult."""
    if r.status == "not_authentic":
        return "\U0001f6ab Attestation doesn't belong to an authentic SecretVM"

    vm_line = (
        f"\u2705 Confirmed an authentic SecretVM, "
        f"vm_type {r.template_name}, artifacts {r.artifacts_ver}, environment {r.env}"
    )
    if r.status == "authentic_match":
        return vm_line + "\n\u2705 Confirmed that the VM is running the specified docker-compose.yaml"

    return vm_line + "\n\U0001f6ab Attestation does not match the specified docker-compose.yaml"


# ---------------------------------------------------------------------------
# SEV-SNP GCTX launch-digest computation
# Ported from sev-snp-measure (IBM, Apache-2.0)
# ---------------------------------------------------------------------------

_SEV_LD_SIZE = 48  # SHA-384 digest size
_SEV_ZEROS = bytes(_SEV_LD_SIZE)
_SEV_VMSA_GPA = 0xFFFFFFFFF000
_SEV_VCPU_SIG_EPYC = 0x00800F12  # amd_cpu_sig(23, 1, 2) covers EPYC/EPYC-v1..v4
_SEV_GUEST_FEATURES = 0x1
_SEV_VCPU_MAP = {"small": 1, "medium": 2, "large": 4, "2xlarge": 8}


def _sev_sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


def _sev_gctx_update(ld: bytes, page_type: int, gpa: int, contents: bytes) -> bytes:
    page_info = (
        ld + contents
        + (0x70).to_bytes(2, "little")
        + page_type.to_bytes(1, "little")
        + (0).to_bytes(1, "little")  # is_imi
        + (0).to_bytes(1, "little")  # vmpl3_perms
        + (0).to_bytes(1, "little")  # vmpl2_perms
        + (0).to_bytes(1, "little")  # vmpl1_perms
        + (0).to_bytes(1, "little")  # reserved
        + gpa.to_bytes(8, "little")
    )
    return _sev_sha384(page_info)


def _sev_gctx_update_normal_pages(ld: bytes, start_gpa: int, data: bytes) -> bytes:
    for i in range(0, len(data), 4096):
        ld = _sev_gctx_update(ld, 0x01, start_gpa + i, _sev_sha384(data[i:i + 4096]))
    return ld


def _sev_gctx_update_vmsa_page(ld: bytes, data: bytes) -> bytes:
    return _sev_gctx_update(ld, 0x02, _SEV_VMSA_GPA, _sev_sha384(data))


def _sev_gctx_update_zero_pages(ld: bytes, gpa: int, size: int) -> bytes:
    for i in range(0, size, 4096):
        ld = _sev_gctx_update(ld, 0x03, gpa + i, _SEV_ZEROS)
    return ld


def _sev_gctx_update_secrets_page(ld: bytes, gpa: int) -> bytes:
    return _sev_gctx_update(ld, 0x05, gpa, _SEV_ZEROS)


def _sev_gctx_update_cpuid_page(ld: bytes, gpa: int) -> bytes:
    return _sev_gctx_update(ld, 0x06, gpa, _SEV_ZEROS)


def _sev_build_hashes_page(kernel_hash_hex: str, initrd_hash_hex: str, append: str, offset_in_page: int) -> bytes:
    """Build 4096-byte kernel-hashes page matching QEMU's SEV hash-table layout."""
    SEV_HASH_TABLE_HEADER_GUID = "9438d606-4f22-4cc9-b479-a793d411fd21"
    SEV_KERNEL_ENTRY_GUID = "4de79437-abd2-427f-b835-d5b172d2045b"
    SEV_INITRD_ENTRY_GUID = "44baf731-3a2f-4bd7-9af1-41e29169781d"
    SEV_CMDLINE_ENTRY_GUID = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a"

    kernel_hash = bytes.fromhex(kernel_hash_hex)
    initrd_hash = bytes.fromhex(initrd_hash_hex) if initrd_hash_hex else hashlib.sha256(b"").digest()
    cmdline_bytes = (append.encode() + b"\x00") if append else b"\x00"
    cmdline_hash = hashlib.sha256(cmdline_bytes).digest()

    def guid_le(g: str) -> bytes:
        return uuid.UUID("{" + g + "}").bytes_le

    def entry(g: str, h: bytes) -> bytes:
        # SevHashTableEntry: guid(16) + length(u16) + hash(32) = 50 bytes
        return guid_le(g) + struct.pack("<H", 50) + h

    # SevHashTable: guid(16) + length(u16) + 3 entries(50 each) = 168 bytes
    ht = (
        guid_le(SEV_HASH_TABLE_HEADER_GUID)
        + struct.pack("<H", 168)
        + entry(SEV_CMDLINE_ENTRY_GUID, cmdline_hash)
        + entry(SEV_INITRD_ENTRY_GUID, initrd_hash)
        + entry(SEV_KERNEL_ENTRY_GUID, kernel_hash)
    )
    # Pad to 16-byte alignment: 168 % 16 = 8 -> 8 padding bytes -> 176 bytes total
    padded = ht + bytes(8)
    return bytes(offset_in_page) + padded + bytes(4096 - offset_in_page - len(padded))


def _sev_build_vmsa_page(eip: int, vcpu_sig: int, guest_features: int) -> bytes:
    """Build 4096-byte VMSA page for QEMU SEV-SNP mode."""
    page = bytearray(4096)

    def w16(off: int, val: int) -> None:
        page[off:off + 2] = struct.pack("<H", val)

    def w32(off: int, val: int) -> None:
        page[off:off + 4] = struct.pack("<I", val)

    def w64(off: int, val: int) -> None:
        page[off:off + 8] = struct.pack("<Q", val)

    def vmcb_seg(off: int, sel: int, attr: int, lim: int, base: int) -> None:
        # VmcbSeg: selector(u16) + attrib(u16) + limit(u32) + base(u64) = 16 bytes
        w16(off, sel); w16(off + 2, attr); w32(off + 4, lim); w64(off + 8, base)

    cs_base = eip & 0xFFFF0000
    rip = eip & 0x0000FFFF
    vmcb_seg(0x000, 0,      0x0093, 0xFFFF, 0)         # es
    vmcb_seg(0x010, 0xF000, 0x009B, 0xFFFF, cs_base)   # cs
    vmcb_seg(0x020, 0,      0x0093, 0xFFFF, 0)         # ss
    vmcb_seg(0x030, 0,      0x0093, 0xFFFF, 0)         # ds
    vmcb_seg(0x040, 0,      0x0093, 0xFFFF, 0)         # fs
    vmcb_seg(0x050, 0,      0x0093, 0xFFFF, 0)         # gs
    vmcb_seg(0x060, 0,      0x0000, 0xFFFF, 0)         # gdtr
    vmcb_seg(0x070, 0,      0x0082, 0xFFFF, 0)         # ldtr
    vmcb_seg(0x080, 0,      0x0000, 0xFFFF, 0)         # idtr
    vmcb_seg(0x090, 0,      0x008B, 0xFFFF, 0)         # tr
    w64(0x0D0, 0x1000)               # efer (SVME)
    w64(0x148, 0x40)                 # cr4  (MCE)
    w64(0x158, 0x10)                 # cr0  (PE)
    w64(0x160, 0x400)                # dr7
    w64(0x168, 0xFFFF0FF0)           # dr6
    w64(0x170, 0x2)                  # rflags
    w64(0x178, rip)                  # rip
    w64(0x268, 0x0007040600070406)   # g_pat
    w64(0x310, vcpu_sig)             # rdx (CPUID sig)
    w64(0x3B0, guest_features)       # sev_features
    w64(0x3E8, 0x1)                  # xcr0
    w32(0x408, 0x1F80)               # mxcsr
    w16(0x410, 0x037F)               # x87_fcw
    return bytes(page)


def _sev_calc_measurement(entry: dict, vcpus: int, cmdline: str) -> str:
    """Compute SEV-SNP launch digest for a registry entry and compose cmdline."""
    ld = bytes.fromhex(entry["ovmf_hash"])

    offset_in_page = entry["sev_hashes_table_gpa"] & 0xFFF
    hashes_page = _sev_build_hashes_page(
        entry["kernel_hash"],
        entry.get("initrd_hash", ""),
        cmdline,
        offset_in_page,
    )

    for sec in entry["ovmf_sections"]:
        gpa = sec["gpa"]
        size = sec["size"]
        stype = sec["section_type"]
        if stype == 1:   # SNP_SEC_MEM
            ld = _sev_gctx_update_zero_pages(ld, gpa, size)
        elif stype == 2:  # SNP_SECRETS
            ld = _sev_gctx_update_secrets_page(ld, gpa)
        elif stype == 3:  # CPUID
            ld = _sev_gctx_update_cpuid_page(ld, gpa)
        elif stype == 4:   # SVSM_CAA
            ld = _sev_gctx_update_zero_pages(ld, gpa, size)
        elif stype == 0x10:  # SNP_KERNEL_HASHES
            ld = _sev_gctx_update_normal_pages(ld, gpa, hashes_page)

    bsp_eip = 0xFFFFFFF0
    ap_eip = entry["sev_es_reset_eip"]
    for i in range(vcpus):
        eip = bsp_eip if i == 0 else ap_eip
        vmsa = _sev_build_vmsa_page(eip, _SEV_VCPU_SIG_EPYC, _SEV_GUEST_FEATURES)
        ld = _sev_gctx_update_vmsa_page(ld, vmsa)

    return ld.hex()


_sev_registry_cache: Optional[list] = None


def _load_sev_registry() -> list:
    global _sev_registry_cache
    if _sev_registry_cache is not None:
        return _sev_registry_cache
    json_path = Path(__file__).parent / "data" / "sev.json"
    with open(json_path, "r", encoding="utf-8") as f:
        _sev_registry_cache = json.load(f)
    return _sev_registry_cache


def _parse_sev_family_id(family_id_bytes: bytes) -> Optional[dict]:
    """Parse family_id field from SNP report -> {vm_type, template_name, vcpus}.

    Expected format: ``"{vm_type}-{template_name}-sev"`` e.g. ``"prod-small-sev"``.
    """
    s = family_id_bytes.rstrip(b"\x00#").decode("utf-8", errors="replace")
    if not s.endswith("-sev"):
        return None
    core = s[:-4]  # strip "-sev"
    idx = core.find("-")
    if idx < 0:
        return None
    vm_type = core[:idx]
    template_name = core[idx + 1:]
    vcpus = _SEV_VCPU_MAP.get(template_name)
    if vcpus is None:
        return None
    return {"vm_type": vm_type, "template_name": template_name, "vcpus": vcpus}


# ---------------------------------------------------------------------------
# SEV-SNP workload verification
# ---------------------------------------------------------------------------


def verify_sev_workload(
    data_or_url: str,
    docker_compose_yaml: str = "",
    docker_files: Optional[bytes] = None,
    docker_files_sha256: Optional[str] = None,
) -> WorkloadResult:
    """Verify that an AMD SEV-SNP quote was produced by a known SecretVM running
    the given docker-compose YAML.

    Args:
        data_or_url: Base64-encoded SEV-SNP report, or a VM URL to fetch quote and compose from.
        docker_compose_yaml: Contents of the docker-compose.yaml file. Auto-fetched if URL.
        docker_files: Optional raw bytes of the docker-files tar archive. SHA-256 is
            computed client-side and appended to the kernel cmdline as
            ``docker_additional_files_hash=<hex>``; the cmdline is hashed into the
            SEV-SNP launch measurement. Ignored if docker_files_sha256 is provided.
        docker_files_sha256: Optional hex SHA-256 digest of the docker-files archive.
            Takes precedence over docker_files.

    Returns:
        :class:`WorkloadResult` with status ``"authentic_match"``,
        ``"authentic_mismatch"``, or ``"not_authentic"``.
    """
    from .url import is_vm_url, fetch_cpu_quote, fetch_docker_compose
    if is_vm_url(data_or_url):
        data = fetch_cpu_quote(data_or_url)
        docker_compose_yaml = docker_compose_yaml or fetch_docker_compose(data_or_url)
    else:
        data = data_or_url
        if not docker_compose_yaml:
            return WorkloadResult(status="not_authentic")

    # Resolve docker-files digest (see init-sev: appended to kernel cmdline
    # as `docker_additional_files_hash=<hex>`, which is hashed into the
    # SEV-SNP launch measurement via the GCTX hash page).
    if docker_files_sha256:
        df_sha = docker_files_sha256.lower().removeprefix("0x")
    elif docker_files is not None:
        df_sha = hashlib.sha256(docker_files).hexdigest()
    else:
        df_sha = None
    try:
        raw = base64.b64decode(data.strip())
    except Exception:
        return WorkloadResult(status="not_authentic")

    if len(raw) < 0x090 + 48:
        return WorkloadResult(status="not_authentic")

    try:
        quote_measurement = raw[0x090:0x090 + 48].hex()
        family = _parse_sev_family_id(raw[0x010:0x020])
        if family is None:
            return WorkloadResult(status="not_authentic")
        image_id = raw[0x020:0x030].rstrip(b"\x00#").decode("utf-8", errors="replace")
    except Exception:
        return WorkloadResult(status="not_authentic")

    try:
        registry = _load_sev_registry()
    except Exception:
        return WorkloadResult(status="not_authentic")

    vm_type = family["vm_type"]
    template_name = family["template_name"]
    vcpus = family["vcpus"]

    # raw SHA256 of compose content (no YAML normalization -- matches jeeves behaviour)
    compose_hash = hashlib.sha256(docker_compose_yaml.encode("utf-8")).hexdigest()

    candidates = [e for e in registry if e.get("vm_type") == vm_type]

    def try_entry(entry: dict) -> bool:
        rh = entry.get("rootfs_hash", "")
        cmdline = f"console=ttyS0 loglevel=7 docker_compose_hash={compose_hash} rootfs_hash={rh}"
        if df_sha:
            cmdline += f" docker_additional_files_hash={df_sha}"
        try:
            return _sev_calc_measurement(entry, vcpus, cmdline) == quote_measurement
        except Exception:
            return False

    version_entries = [e for e in candidates if e.get("artifacts_ver") == image_id] if image_id else []

    # Try version-specific entries first (fast path when image_id is set)
    for entry in version_entries:
        if try_entry(entry):
            return WorkloadResult(
                status="authentic_match",
                template_name=template_name,
                vm_type=template_name,
                artifacts_ver=entry["artifacts_ver"],
                env=vm_type,
            )

    # Fallback: try remaining entries for this vm_type
    for entry in candidates:
        if image_id and entry.get("artifacts_ver") == image_id:
            continue  # already tried above
        if try_entry(entry):
            return WorkloadResult(
                status="authentic_match",
                template_name=template_name,
                vm_type=template_name,
                artifacts_ver=entry.get("artifacts_ver", ""),
                env=vm_type,
            )

    # No compose match. If the version is in the registry the VM is authentic
    # but the provided compose doesn't match the measurement.
    if version_entries:
        best = version_entries[0]
        return WorkloadResult(
            status="authentic_mismatch",
            template_name=template_name,
            vm_type=template_name,
            artifacts_ver=best.get("artifacts_ver"),
            env=vm_type,
        )
    return WorkloadResult(status="not_authentic")


# ---------------------------------------------------------------------------
# Generic workload verifier (auto-detects TDX vs SEV-SNP)
# ---------------------------------------------------------------------------


def verify_workload(
    data_or_url: str,
    docker_compose_yaml: str = "",
    docker_files: Optional[bytes] = None,
    docker_files_sha256: Optional[str] = None,
) -> WorkloadResult:
    """Verify that a CPU quote was produced by a known SecretVM running the
    given docker-compose YAML.

    Automatically detects whether *data_or_url* is an Intel TDX (hex) or AMD
    SEV-SNP (base64) quote and delegates to the appropriate lower-level function.
    If a VM URL is passed, fetches the quote and docker-compose automatically.

    Args:
        data_or_url: Quote data or VM URL. If URL, fetches /cpu and /docker-compose.
        docker_compose_yaml: Contents of the docker-compose.yaml file. Auto-fetched if URL.

    Returns:
        :class:`WorkloadResult` with status ``"authentic_match"``,
        ``"authentic_mismatch"``, or ``"not_authentic"``.
    """
    from .url import is_vm_url, fetch_cpu_quote, fetch_docker_compose
    if is_vm_url(data_or_url):
        data = fetch_cpu_quote(data_or_url)
        docker_compose_yaml = docker_compose_yaml or fetch_docker_compose(data_or_url)
    else:
        data = data_or_url
        if not docker_compose_yaml:
            return WorkloadResult(status="not_authentic")
    quote_type = _detect_cpu_quote_type(data)
    if quote_type == "TDX":
        return verify_tdx_workload(data, docker_compose_yaml, docker_files, docker_files_sha256)
    if quote_type == "SEV-SNP":
        return verify_sev_workload(data, docker_compose_yaml, docker_files, docker_files_sha256)
    return WorkloadResult(status="not_authentic")
