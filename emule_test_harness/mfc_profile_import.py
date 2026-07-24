"""Create a fresh eMuleBB Rust profile from a stock eMule config directory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from emule_test_harness import kad_nodes, mfc_known_met, rust_metadata, soak_launch

SERVER_MET_HEADER = 0x0E
SERVER_MET_HEADER_LARGEFILES = 0xE0
ST_SERVERNAME = 0x01
PREFERENCES_DAT_VERSION = 0x14
SHARED_STARTUP_CACHE_MAGIC = 0x43484853
SHARED_STARTUP_CACHE_VERSION = 4
FILE_ID_BYTES = 16
USN_FILE_REFERENCE_BYTES = 16


def import_stock_mfc_profile(
    *,
    rust_repo: Path,
    emule_config_dir: Path,
    rust_profile_dir: Path,
    kad_bootstrap_limit: int = 40,
    import_user_hash: bool = False,
    scan_shared_roots: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Create and seed a new Rust profile from stock eMule profile files."""

    if not emule_config_dir.is_dir():
        raise ValueError(f"eMule config directory does not exist: {emule_config_dir}")
    _require_new_profile_target(rust_profile_dir)

    known_met = emule_config_dir / "known.met"
    shareddir = emule_config_dir / "shareddir.dat"
    if not known_met.is_file():
        raise ValueError(f"stock eMule profile is missing known.met: {known_met}")
    if not shareddir.is_file():
        raise ValueError(f"stock eMule profile is missing shareddir.dat: {shareddir}")

    known2_64_met = emule_config_dir / "known2_64.met"
    server_met = emule_config_dir / "server.met"
    nodes_dat = emule_config_dir / "nodes.dat"
    preferences_dat = emule_config_dir / "preferences.dat"
    metadata_db = rust_profile_dir / rust_metadata.RUST_PROFILE_METADATA_FILE

    root_entries = _load_recursive_root_entries(emule_config_dir)
    seed_roots = [
        {
            "path": mfc_known_met.normal_windows_display_path(soak_launch.shared_root_path(root)),
            "monitorOwned": False,
            "shareable": True,
            "accessible": True,
        }
        for root in root_entries
        if soak_launch.shared_root_path(root).strip("\\/")
    ]
    shared_cache = emule_config_dir / "sharedcache.dat"
    shared_file_candidates = load_sharedcache_candidates(shared_cache) if shared_cache.is_file() else []

    servers = parse_server_met(server_met) if server_met.is_file() else []
    kad_endpoints = kad_nodes.load_bootstrap_endpoints(nodes_dat, limit=kad_bootstrap_limit) if nodes_dat.is_file() else []
    user_hash = read_preferences_dat_user_hash(preferences_dat) if import_user_hash and preferences_dat.is_file() else None

    if not dry_run:
        rust_metadata.create_metadata_db(rust_repo, metadata_db)
        rust_metadata.seed_shared_directory_roots(metadata_db, seed_roots)
        for server in servers:
            rust_metadata.seed_server(metadata_db, server)
        rust_metadata.replace_kad_bootstrap_endpoints(metadata_db, kad_endpoints)
        if user_hash is not None:
            rust_metadata.seed_local_user_hash(metadata_db, user_hash)

    hash_summary = mfc_known_met.import_mfc_known_met_hashes(
        rust_repo=rust_repo,
        metadata_db=metadata_db,
        known_met=known_met,
        known2_64_met=known2_64_met if known2_64_met.is_file() else None,
        shared_roots=root_entries,
        shared_file_candidates=shared_file_candidates,
        scan_shared_roots=scan_shared_roots,
        dry_run=dry_run,
    )

    return {
        "schemaVersion": 1,
        "tool": "import-mfc-profile-to-rust.py",
        "dryRun": dry_run,
        "emuleConfigDir": str(emule_config_dir),
        "rustProfileDir": str(rust_profile_dir),
        "metadataDb": str(metadata_db),
        "sharedRoots": len(seed_roots),
        "accessibleSharedRoots": sum(1 for root in seed_roots if root["accessible"]),
        "sharedCacheCandidates": len(shared_file_candidates),
        "servers": len(servers),
        "kadBootstrapEndpoints": len(kad_endpoints),
        "importedUserHash": user_hash is not None,
        "hashes": hash_summary,
    }


def parse_server_met(path: Path) -> list[dict[str, object]]:
    """Parse stock ``server.met`` into Rust metadata seed rows."""

    reader = mfc_known_met.BinaryReader(path.read_bytes())
    version = reader.u8()
    if version not in {SERVER_MET_HEADER, SERVER_MET_HEADER_LARGEFILES}:
        raise ValueError(f"unsupported server.met header 0x{version:02x}")
    count = reader.u32()
    if count > 1_000_000:
        raise ValueError(f"implausible server.met count {count}")
    servers: list[dict[str, object]] = []
    for _ in range(count):
        raw_ip = reader.read(4)
        port = reader.u16()
        tag_count = reader.u32()
        name = ""
        for _ in range(tag_count):
            tag_name, tag_value = mfc_known_met._read_tag(reader)
            if tag_name == ST_SERVERNAME and isinstance(tag_value, str):
                name = tag_value
        if raw_ip == b"\x00\x00\x00\x00" or port == 0:
            continue
        servers.append(
            {
                "address": ".".join(str(byte) for byte in raw_ip),
                "port": port,
                "name": name,
                "serverPriority": "normal",
                "staticServer": True,
                "enabled": True,
            }
        )
    if reader.remaining() != 0:
        raise ValueError("server.met has trailing bytes")
    return servers


def read_preferences_dat_user_hash(path: Path) -> bytes:
    """Return the 16-byte stock eMule user hash from ``preferences.dat``."""

    reader = mfc_known_met.BinaryReader(path.read_bytes())
    version = reader.u8()
    if version != PREFERENCES_DAT_VERSION:
        raise ValueError(f"unsupported preferences.dat header 0x{version:02x}")
    return reader.read(16)


def load_sharedcache_candidates(path: Path) -> list[mfc_known_met.SharedFileCandidate]:
    """Load cached shared-file paths from MFC ``sharedcache.dat`` without touching disk files."""

    reader = mfc_known_met.BinaryReader(path.read_bytes())
    magic = reader.u32()
    version = reader.u16()
    if magic != SHARED_STARTUP_CACHE_MAGIC or version != SHARED_STARTUP_CACHE_VERSION:
        raise ValueError(f"unsupported sharedcache.dat header 0x{magic:08x}/0x{version:04x}")
    volume_count = reader.u32()
    if volume_count > 1024:
        raise ValueError(f"implausible sharedcache.dat volume count {volume_count}")
    for _ in range(volume_count):
        _read_startup_cache_string(reader)
        reader.u64()
        reader.u64()
        reader.u64()

    directory_count = reader.u32()
    if directory_count > 100_000:
        raise ValueError(f"implausible sharedcache.dat directory count {directory_count}")
    candidates: list[mfc_known_met.SharedFileCandidate] = []
    for _ in range(directory_count):
        directory = _read_startup_cache_string(reader)
        reader.u8()
        reader.u8()
        reader.u64()
        reader.read(FILE_ID_BYTES)
        reader.u64()
        reader.u8()
        _read_startup_cache_string(reader)
        reader.read(USN_FILE_REFERENCE_BYTES)
        file_count = reader.u32()
        if file_count > 1_000_000:
            raise ValueError(f"implausible sharedcache.dat file count {file_count}")
        for _ in range(file_count):
            leaf = _read_startup_cache_string(reader)
            mtime_s = reader.u64()
            size_bytes = reader.u64()
            if not directory or not leaf or size_bytes <= 0:
                continue
            normalized_path = mfc_known_met.normal_windows_display_path(str(Path(directory) / leaf))
            candidates.append(
                mfc_known_met.SharedFileCandidate(
                    path=Path(normalized_path),
                    size_bytes=size_bytes,
                    mtime_s=mtime_s,
                    mtime_ms=mtime_s * 1000,
                )
            )
    if reader.remaining() != 0:
        raise ValueError("sharedcache.dat has trailing bytes")
    return candidates


def _require_new_profile_target(path: Path) -> None:
    if path.exists() and not path.is_dir():
        raise ValueError(f"Rust profile target exists and is not a directory: {path}")
    if path.exists() and any(path.iterdir()):
        raise ValueError(f"Rust profile target must be new or empty: {path}")


def _read_startup_cache_string(reader: mfc_known_met.BinaryReader) -> str:
    char_count = reader.u32()
    if char_count > 32768:
        raise ValueError(f"implausible sharedcache.dat string length {char_count}")
    if char_count == 0:
        return ""
    return reader.read(char_count * 2).decode("utf-16-le", errors="strict")


def _load_recursive_root_entries(emule_config_dir: Path) -> list[object]:
    monitored = emule_config_dir / "shareddir.monitored.dat"
    roots = soak_launch.load_shareddir_root_entries(monitored) if monitored.is_file() else []
    if not roots:
        roots = soak_launch.load_shareddir_root_entries(emule_config_dir / "shareddir.dat")
    recursive_roots = [{"path": soak_launch.shared_root_path(root), "recursive": True} for root in roots]
    return soak_launch.dedupe_shared_roots(recursive_roots)
