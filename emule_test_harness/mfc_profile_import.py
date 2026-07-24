"""Create a fresh eMuleBB Rust profile from a stock eMule config directory."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from emule_test_harness import kad_nodes, mfc_known_met, rust_client, rust_metadata, soak_launch

SERVER_MET_HEADER = 0x0E
SERVER_MET_HEADER_LARGEFILES = 0xE0
ST_SERVERNAME = 0x01
PREFERENCES_DAT_VERSION = 0x14
DEFAULT_REST_ADDR = ""
DEFAULT_REST_PORT = 58381
DEFAULT_API_KEY = soak_launch.RUST_API_KEY
DEFAULT_ED2K_PORT = 4662
DEFAULT_KAD_PORT = 4672
DEFAULT_P2P_BIND_INTERFACE = "hide.me"


def import_stock_mfc_profile(
    *,
    rust_repo: Path,
    emule_config_dir: Path,
    rust_profile_dir: Path,
    kad_bootstrap_limit: int = 40,
    import_user_hash: bool = False,
    rest_addr: str = DEFAULT_REST_ADDR,
    rest_port: int = DEFAULT_REST_PORT,
    api_key: str = DEFAULT_API_KEY,
    p2p_bind_ip: str | None = None,
    p2p_bind_interface: str | None = DEFAULT_P2P_BIND_INTERFACE,
    ed2k_port: int = DEFAULT_ED2K_PORT,
    kad_port: int = DEFAULT_KAD_PORT,
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

    root_entries = _load_recursive_root_entries(shareddir)
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

    servers = parse_server_met(server_met) if server_met.is_file() else []
    kad_endpoints = kad_nodes.load_bootstrap_endpoints(nodes_dat, limit=kad_bootstrap_limit) if nodes_dat.is_file() else []
    user_hash = read_preferences_dat_user_hash(preferences_dat) if import_user_hash and preferences_dat.is_file() else None
    resolved_rest_addr = rest_addr.strip() or os.environ.get("X_LOCAL_IP", "").strip()
    if not resolved_rest_addr:
        raise RuntimeError("X_LOCAL_IP must be set or --rest-addr supplied for Rust REST binding.")
    resolved_p2p_bind_ip = p2p_bind_ip.strip() if p2p_bind_ip else None
    resolved_p2p_bind_interface = p2p_bind_interface.strip() if p2p_bind_interface else None
    if not resolved_p2p_bind_ip and not resolved_p2p_bind_interface:
        raise RuntimeError("P2P binding requires --p2p-bind-interface or --p2p-bind-ip.")

    if not dry_run:
        rust_metadata.create_metadata_db(rust_repo, metadata_db)
        rust_client.write_rust_profile(
            rust_profile_dir,
            rust_repo=rust_repo,
            rest_addr=resolved_rest_addr,
            rest_port=rest_port,
            api_key=api_key,
            p2p_bind_ip=resolved_p2p_bind_ip,
            p2p_bind_interface=resolved_p2p_bind_interface,
            ed2k_port=ed2k_port,
            kad_port=kad_port,
        )
        rust_metadata.seed_shared_directory_roots(metadata_db, seed_roots)
        for server in servers:
            rust_metadata.seed_server(metadata_db, server)
        rust_metadata.replace_kad_bootstrap_endpoints(metadata_db, kad_endpoints)
        if user_hash is not None:
            rust_metadata.seed_local_user_hash(metadata_db, user_hash)

    hash_summary = mfc_known_met.import_mfc_known_met_cache(
        rust_repo=rust_repo,
        metadata_db=metadata_db,
        known_met=known_met,
        known2_64_met=known2_64_met if known2_64_met.is_file() else None,
        dry_run=dry_run,
    )

    return {
        "schemaVersion": 1,
        "tool": "import-mfc-profile-to-rust.py",
        "dryRun": dry_run,
        "emuleConfigDir": str(emule_config_dir),
        "rustProfileDir": str(rust_profile_dir),
        "metadataDb": str(metadata_db),
        "profileSettings": str(rust_profile_dir / rust_client.RUST_PROFILE_SETTINGS_FILE),
        "restBaseUrl": f"http://{resolved_rest_addr}:{rest_port}/api/v1",
        "p2pBindIp": resolved_p2p_bind_ip,
        "p2pBindInterface": resolved_p2p_bind_interface,
        "ed2kPort": ed2k_port,
        "kadPort": kad_port,
        "sharedRoots": len(seed_roots),
        "accessibleSharedRoots": sum(1 for root in seed_roots if root["accessible"]),
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


def _require_new_profile_target(path: Path) -> None:
    if path.exists() and not path.is_dir():
        raise ValueError(f"Rust profile target exists and is not a directory: {path}")
    if path.exists() and any(path.iterdir()):
        raise ValueError(f"Rust profile target must be new or empty: {path}")


def _load_recursive_root_entries(shareddir: Path) -> list[object]:
    roots = soak_launch.load_shareddir_roots(shareddir)
    collapsed = _collapse_stock_shareddir_roots(roots)
    recursive_roots = [{"path": root, "recursive": True} for root in collapsed]
    return soak_launch.dedupe_shared_roots(recursive_roots)


def _collapse_stock_shareddir_roots(roots: list[str]) -> list[str]:
    display_roots = [
        _root_display(soak_launch.normalize_shared_root(root))
        for root in roots
        if soak_launch.shared_root_path(root).strip("\\/")
    ]
    listed_order = {_root_key(root): index for index, root in enumerate(display_roots)}
    listed = set(listed_order)
    if not listed:
        return []
    candidate_displays = {
        _root_key(parent): parent
        for root in display_roots
        for parent in _candidate_paths(root)
    }
    candidates = sorted(
        candidate_displays,
        key=lambda key: candidate_displays[key].count(os.sep),
    )
    selected: list[str] = []
    for candidate in candidates:
        if any(_is_key_under(candidate, existing) for existing in selected):
            continue
        if candidate in listed or _directory_subtree_is_fully_listed(candidate_displays[candidate], listed):
            selected.append(candidate)
    selected.sort(key=lambda key: min(index for listed_key, index in listed_order.items() if _is_key_under(listed_key, key)))
    return [_display_root_from_key(candidate_displays[key]) for key in selected]


def _directory_subtree_is_fully_listed(candidate: str, listed: set[str]) -> bool:
    immediate_listed_children = 0
    try:
        with os.scandir(candidate) as iterator:
            children = [
                entry.path
                for entry in iterator
                if entry.is_dir(follow_symlinks=False)
            ]
    except OSError:
        return False
    if not children:
        return False
    stack = children[:]
    for child in children:
        if _root_key(child) in listed:
            immediate_listed_children += 1
    if immediate_listed_children < 2:
        return False
    while stack:
        current = stack.pop()
        key = _root_key(current)
        if key not in listed:
            return False
        try:
            with os.scandir(current) as iterator:
                stack.extend(
                    entry.path
                    for entry in iterator
                    if entry.is_dir(follow_symlinks=False)
                )
        except OSError:
            return False
    return True


def _candidate_paths(path: str) -> list[str]:
    current = _root_display(path)
    parent = os.path.dirname(current)
    if parent == current or not parent:
        return [current]
    return [parent, current]


def _root_display(path: str) -> str:
    display = mfc_known_met.normal_windows_display_path(str(path))
    return os.path.abspath(display.rstrip("\\/"))


def _root_key(path: str) -> str:
    return os.path.normcase(_root_display(path))


def _is_key_under(candidate: str, root: str) -> bool:
    if candidate == root:
        return True
    try:
        return os.path.commonpath([candidate, root]) == root
    except ValueError:
        return False


def _display_root_from_key(key: str) -> str:
    return soak_launch.normalize_shared_root(mfc_known_met.normal_windows_display_path(key))
