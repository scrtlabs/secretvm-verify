#!/usr/bin/env python3
"""
Fetch SEV-SNP artifact metadata from a GitHub release and populate artifacts_registry/sev.json.

Usage:
    python3 scripts/fetch_sev_artifacts.py <version> [options]

Examples:
    python3 scripts/fetch_sev_artifacts.py v0.0.25
    python3 scripts/fetch_sev_artifacts.py v0.0.26-beta.2 --dry-run
    python3 scripts/fetch_sev_artifacts.py v0.0.25 --github-token ghp_xxx
    python3 scripts/fetch_sev_artifacts.py v0.0.25 --sev-snp-measure-path /path/to/sev-snp-measure
"""

import argparse
import json
import os
import sys
import tempfile
import urllib.request
import urllib.error
from pathlib import Path


GITHUB_API = "https://api.github.com/repos/scrtlabs/secret-vm-build/releases/tags/{version}"
VCPU_TYPE = "EPYC"

# Candidate paths to look for the sev-snp-measure library, relative to this script or common locations
SEV_SNP_MEASURE_CANDIDATES = [
    # sibling of the secretvm-verify repo
    Path(__file__).parent.parent.parent / "dstack-amd-feature" / "sev-snp-measure",
    # common dev checkout
    Path.home() / "sev-snp-measure",
    Path("/opt/sev-snp-measure"),
]


def find_sev_snp_measure() -> Path:
    for candidate in SEV_SNP_MEASURE_CANDIDATES:
        if (candidate / "sevsnpmeasure" / "ovmf.py").exists():
            return candidate
    raise FileNotFoundError(
        "sev-snp-measure library not found. Use --sev-snp-measure-path to specify its location.\n"
        "Clone it from: https://github.com/virtee/sev-snp-measure"
    )


def fetch_release_assets(version: str, token: str | None) -> dict[str, str]:
    """Fetch asset digest map {asset_name: sha256_hex} from the GitHub release API."""
    url = GITHUB_API.format(version=version)
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            sys.exit(f"Release '{version}' not found on GitHub (HTTP 404). Check the version tag.")
        elif e.code == 403:
            sys.exit("GitHub API rate limit exceeded or access forbidden. Use --github-token to authenticate.")
        raise

    asset_map: dict[str, str] = {}
    for asset in data.get("assets", []):
        name = asset["name"]
        digest = asset.get("digest", "")
        if digest.startswith("sha256:"):
            asset_map[name] = digest[len("sha256:"):]
        else:
            # no digest in API response (older GitHub API behaviour); record download URL
            asset_map[f"__url_{name}"] = asset["browser_download_url"]

    return asset_map


def download_file(url: str, dest: str, token: str | None) -> None:
    """Download a file from a URL to dest path."""
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    print(f"  Downloading {url} …", flush=True)
    with urllib.request.urlopen(req, timeout=120) as resp:
        with open(dest, "wb") as f:
            while chunk := resp.read(1 << 20):
                f.write(chunk)


def get_ovmf_hash_and_meta(ovmf_path: str, sev_snp_measure_path: Path) -> dict:
    """
    Download & parse the OVMF .fd file to extract:
      - ovmf_hash (GCTX LD seed, hex-encoded SHA-384)
      - sev_hashes_table_gpa
      - sev_es_reset_eip
      - ovmf_sections list
    """
    if str(sev_snp_measure_path) not in sys.path:
        sys.path.insert(0, str(sev_snp_measure_path))

    from sevsnpmeasure.ovmf import OVMF  # type: ignore
    from sevsnpmeasure.guest import calc_snp_ovmf_hash  # type: ignore

    print("  Parsing OVMF …", flush=True)
    ovmf_hash_bytes = calc_snp_ovmf_hash(ovmf_path)
    ovmf_hash = ovmf_hash_bytes.hex()

    ovmf_obj = OVMF(ovmf_path)
    sev_hashes_table_gpa = ovmf_obj.sev_hashes_table_gpa()
    sev_es_reset_eip = ovmf_obj.sev_es_reset_eip()

    sections = [
        {
            "gpa": int(desc.gpa),
            "size": int(desc.size),
            "section_type": int(desc.section_type().value),
        }
        for desc in ovmf_obj.metadata_items()
    ]

    return {
        "ovmf_hash": ovmf_hash,
        "sev_hashes_table_gpa": sev_hashes_table_gpa,
        "sev_es_reset_eip": sev_es_reset_eip,
        "ovmf_sections": sections,
    }


def build_entries(version: str, asset_map: dict[str, str], ovmf_meta: dict) -> list[dict]:
    """Build the prod and dev sev.json entries for the given version."""
    def _get_hash(name: str) -> str:
        h = asset_map.get(name)
        if not h:
            sys.exit(f"Asset '{name}' not found in release '{version}'. Available assets:\n  "
                     + "\n  ".join(k for k in asset_map if not k.startswith("__url_")))
        return h

    kernel_hash = _get_hash(f"bzImage-{version}-sev")
    initrd_hash = _get_hash(f"initramfs-{version}-sev.cpio.gz")
    rootfs_prod = _get_hash(f"rootfs-prod-{version}-sev.iso")
    rootfs_dev = _get_hash(f"rootfs-dev-{version}-sev.iso")

    base = {
        "artifacts_ver": version,
        "kernel_hash": kernel_hash,
        "initrd_hash": initrd_hash,
        "vcpu_type": VCPU_TYPE,
        **ovmf_meta,
    }

    return [
        {"vm_type": "prod", "rootfs_hash": rootfs_prod, **base},
        {"vm_type": "dev", "rootfs_hash": rootfs_dev, **base},
    ]


def update_sev_json(registry_path: Path, new_entries: list[dict], dry_run: bool) -> None:
    """Load sev.json, remove any entries for the same (vm_type, artifacts_ver), append new ones."""
    if registry_path.exists():
        existing = json.loads(registry_path.read_text())
    else:
        existing = []

    version = new_entries[0]["artifacts_ver"]
    versions_in_new = {e["artifacts_ver"] for e in new_entries}
    vm_types_in_new = {e["vm_type"] for e in new_entries}

    # Remove entries that will be replaced
    kept = [
        e for e in existing
        if not (e.get("artifacts_ver") in versions_in_new and e.get("vm_type") in vm_types_in_new)
    ]
    removed = len(existing) - len(kept)
    merged = kept + new_entries

    output = json.dumps(merged, indent=2)

    if dry_run:
        print("\n--- DRY RUN: resulting sev.json entries for this version ---")
        print(json.dumps(new_entries, indent=2))
        if removed:
            print(f"\n(would replace {removed} existing entries for {version})")
        return

    registry_path.write_text(output + "\n")
    action = f"replaced {removed} existing +  added" if removed else "added"
    print(f"\nWrote {registry_path}: {action} {len(new_entries)} entries for {version}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Populate artifacts_registry/sev.json from a GitHub release.")
    parser.add_argument("version", help="Release version tag, e.g. v0.0.25 or v0.0.26-beta.2")
    parser.add_argument("--github-token", metavar="TOKEN", default=os.environ.get("GITHUB_TOKEN"),
                        help="GitHub personal access token (or set GITHUB_TOKEN env var)")
    parser.add_argument("--sev-snp-measure-path", metavar="PATH", default=None,
                        help="Path to the sev-snp-measure repo checkout")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be written without modifying sev.json")
    args = parser.parse_args()

    version = args.version
    token = args.github_token

    # Locate sev-snp-measure
    if args.sev_snp_measure_path:
        snp_path = Path(args.sev_snp_measure_path)
        if not (snp_path / "sevsnpmeasure" / "ovmf.py").exists():
            sys.exit(f"sev-snp-measure not found at: {snp_path}")
    else:
        snp_path = find_sev_snp_measure()
    print(f"Using sev-snp-measure at: {snp_path}")

    # Locate registry file (relative to this script)
    registry_path = Path(__file__).parent.parent / "artifacts_registry" / "sev.json"

    print(f"\nFetching release assets for {version} …")
    asset_map = fetch_release_assets(version, token)

    ovmf_asset_name = f"ovmf-{version}-sev.fd"
    ovmf_url_key = f"__url_{ovmf_asset_name}"

    with tempfile.TemporaryDirectory() as tmpdir:
        ovmf_tmp = os.path.join(tmpdir, ovmf_asset_name)

        if ovmf_url_key in asset_map:
            # Older GitHub API — no digest; must download
            download_file(asset_map[ovmf_url_key], ovmf_tmp, token)
        elif ovmf_asset_name in asset_map:
            # We have the digest but still need to download to parse the binary
            # Find the download URL from the raw asset list
            url = f"https://github.com/scrtlabs/secret-vm-build/releases/download/{version}/{ovmf_asset_name}"
            download_file(url, ovmf_tmp, token)
        else:
            sys.exit(f"OVMF asset '{ovmf_asset_name}' not found in release '{version}'.")

        print("\nComputing OVMF hash and extracting metadata …")
        ovmf_meta = get_ovmf_hash_and_meta(ovmf_tmp, snp_path)

    print("\nBuilding registry entries …")
    new_entries = build_entries(version, asset_map, ovmf_meta)

    for e in new_entries:
        print(f"  [{e['vm_type']:4}]  kernel={e['kernel_hash'][:16]}…  "
              f"initrd={e['initrd_hash'][:16]}…  rootfs={e['rootfs_hash'][:16]}…")
    print(f"  ovmf_hash={ovmf_meta['ovmf_hash'][:32]}…")
    print(f"  sev_hashes_table_gpa={ovmf_meta['sev_hashes_table_gpa']}  "
          f"sev_es_reset_eip={ovmf_meta['sev_es_reset_eip']}")
    print(f"  ovmf_sections ({len(ovmf_meta['ovmf_sections'])} items): "
          + ", ".join(f"type={s['section_type']}" for s in ovmf_meta["ovmf_sections"]))

    update_sev_json(registry_path, new_entries, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
