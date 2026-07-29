"""Shared eMuleBB Rust launch and profile helpers for harness scenarios."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .paths import get_workspace_output_root
from . import rust_metadata

CARGO_TARGET_DIR_ENV = "CARGO_TARGET_DIR"
RUST_PROFILE_SETTINGS_FILE = "emulebb-rust-settings.toml"
RUST_PROFILE_METADATA_FILE = rust_metadata.RUST_PROFILE_METADATA_FILE


def get_required_cargo_target_dir() -> Path:
    """Returns the caller-provided canonical Cargo target directory."""

    raw_target_dir = os.environ.get(CARGO_TARGET_DIR_ENV, "").strip()
    if not raw_target_dir:
        raise RuntimeError(f"{CARGO_TARGET_DIR_ENV} must be set before running Rust harness commands.")
    target_dir = Path(raw_target_dir).resolve()
    if not target_dir.exists():
        raise RuntimeError(f"{CARGO_TARGET_DIR_ENV} must point to an existing directory: {target_dir}")
    expected = (get_workspace_output_root() / "builds" / "rust" / "target").resolve()
    if os.path.normcase(str(target_dir)) != os.path.normcase(str(expected)):
        raise RuntimeError(f"{CARGO_TARGET_DIR_ENV} must be {expected}, got {target_dir}.")
    return target_dir


def rust_cargo_env() -> dict[str, str]:
    """Returns the process environment after validating the canonical Cargo target dir."""

    env = os.environ.copy()
    get_required_cargo_target_dir()
    return env


def write_rust_profile(
    profile_dir: Path,
    *,
    rust_repo: Path,
    incoming_dir: Path | None = None,
    rest_addr: str,
    rest_port: int,
    api_key: str,
    p2p_bind_ip: str | None = None,
    p2p_bind_interface: str | None = None,
    ed2k_port: int | None = None,
    kad_port: int | None = None,
    server_endpoint: str | None = None,
    server_entry: dict[str, object] | None = None,
    obfuscation_enabled: bool = True,
    connect_timeout_secs: int = 10,
    reconnect_interval_secs: int = 60,
    kad_bootstrap_nodes: list[str] | None = None,
    kad_bootstrap_min_routing_contacts: int = 10,
    enable_udp_reask: bool = False,
    publish_emule_rust_identity: bool = False,
    upload_active_slots: int | None = None,
    nat_enabled: bool | None = None,
    nat_require_initial_mapping: bool | None = None,
    replace_servers: bool = False,
    vpn_guard_mode: str = "off",
    vpn_guard_allowed_public_ip_cidrs: str = "",
    initial_shared_directory_reload: bool | None = None,
) -> None:
    """Writes a minimal eMuleBB Rust profile for local harness runs.

    ``vpn_guard_mode`` (``off`` / ``block``) + ``vpn_guard_allowed_public_ip_cidrs``
    populate the ``vpn.guard`` settings section: ``block`` fails the P2P data
    plane closed when the tunnel binding is lost, and the CIDR allowlist
    validates the public exit (VpnGuardSettings, emulebb-daemon/src/lib.rs).
    """

    profile_dir.mkdir(parents=True, exist_ok=True)
    settings_path = profile_dir / RUST_PROFILE_SETTINGS_FILE
    metadata_path = profile_dir / RUST_PROFILE_METADATA_FILE
    if not metadata_path.exists():
        rust_metadata.create_metadata_db(rust_repo, metadata_path)

    lines = ["[rest]", f'bindAddr = "{rest_addr}:{rest_port}"', f'apiKey = "{api_key}"', ""]
    settings_path.write_text("\n".join(lines), encoding="utf-8")

    daemon_settings: dict[str, object] = {}
    if incoming_dir is not None:
        daemon_settings["incomingDir"] = incoming_dir.as_posix()
    if p2p_bind_ip is not None:
        daemon_settings["p2pBindIp"] = p2p_bind_ip
    if p2p_bind_interface is not None:
        daemon_settings["p2pBindInterface"] = p2p_bind_interface
    if initial_shared_directory_reload is not None:
        daemon_settings["initialSharedDirectoryReload"] = initial_shared_directory_reload
    if daemon_settings:
        rust_metadata.replace_settings_section(metadata_path, "daemon", daemon_settings)

    if kad_bootstrap_nodes:
        rust_metadata.replace_kad_bootstrap_endpoints(metadata_path, kad_bootstrap_nodes)

    kad_settings: dict[str, object] = {}
    if kad_port is not None:
        kad_settings["listenPort"] = kad_port
    if kad_bootstrap_min_routing_contacts != 10:
        kad_settings["bootstrapMinRoutingContacts"] = kad_bootstrap_min_routing_contacts
    if kad_settings:
        rust_metadata.replace_settings_section(metadata_path, "kad", kad_settings)

    ed2k_settings: dict[str, object] = {}
    if server_endpoint is not None:
        if (p2p_bind_ip is None and p2p_bind_interface is None) or ed2k_port is None or kad_port is None:
            raise ValueError("ED2K Rust profiles require p2p_bind_ip and/or p2p_bind_interface, ed2k_port, and kad_port.")
    if server_entry is not None:
        if server_endpoint is None:
            raise ValueError("ED2K Rust serverEntry requires server_endpoint.")
        if "host" not in server_entry or "port" not in server_entry:
            raise ValueError("ED2K Rust serverEntry requires host and port.")
    if ed2k_port is not None:
        ed2k_settings["listenPort"] = ed2k_port
    if server_endpoint is not None:
        ed2k_settings.update(
            {
                "obfuscationEnabled": obfuscation_enabled,
                "connectTimeoutSecs": connect_timeout_secs,
                "reconnectIntervalSecs": reconnect_interval_secs,
                "enableUdpReask": enable_udp_reask,
                # Client identity on the wire: false (default) impersonates a stock
                # eMule Community 0.7-series client (6-tag hello, no CT_MOD_VERSION);
                # true publishes the emulebb-rust mod identity. Kept explicit so the
                # impersonation choice is visible + flippable per soak run.
                "publishEmuleRustIdentity": publish_emule_rust_identity,
            }
        )
    # Optional upload-queue policy override. activeSlots=0 forces every
    # requester into the waiting queue (used to make a peer UDP-reask us).
    if upload_active_slots is not None:
        ed2k_settings["uploadQueue"] = {"activeSlots": upload_active_slots}
    if ed2k_settings:
        rust_metadata.replace_settings_section(metadata_path, "ed2k", ed2k_settings)

    if replace_servers:
        rust_metadata.clear_servers(metadata_path)

    if server_entry is not None:
        rust_metadata.seed_server(metadata_path, server_entry)
    elif server_endpoint is not None:
        rust_metadata.seed_server(metadata_path, server_from_endpoint(server_endpoint))

    nat_settings: dict[str, object] = {}
    if nat_enabled is not None:
        nat_settings["enabled"] = nat_enabled
    if nat_require_initial_mapping is not None:
        nat_settings["requireInitialMapping"] = nat_require_initial_mapping
    if nat_settings:
        rust_metadata.replace_settings_section(metadata_path, "nat", nat_settings)

    # VPN Guard: activate the fail-closed data-plane guard + public-exit CIDR
    # allowlist for public live-test runs (workspace Live Test Network Policy).
    guard_mode = (vpn_guard_mode or "off").strip().lower()
    guard_enabled = guard_mode == "block"
    rust_metadata.replace_settings_section(
        metadata_path,
        "vpn.guard",
        {
            "enabled": guard_enabled,
            "mode": "block" if guard_enabled else "off",
            "allowedPublicIpCidrs": vpn_guard_allowed_public_ip_cidrs or "",
        },
    )


def server_from_endpoint(endpoint: str) -> dict[str, object]:
    """Returns a SQLite server seed row from a ``host:port`` endpoint."""

    host, separator, raw_port = endpoint.rpartition(":")
    if not separator or not host:
        raise ValueError(f"ED2K Rust server endpoint must be host:port, got {endpoint!r}.")
    return {"host": host, "port": int(raw_port), "name": endpoint}


def start_rust_client(
    repo: Path, profile_dir: Path, output_path: Path, features: str | None = None
) -> subprocess.Popen[str]:
    """Starts `emulebb-rust` through Cargo using the shared workspace target directory.

    ``features`` forwards a Cargo feature list (e.g. ``packet-diagnostics``) so a
    harness can compile in the ed2k_packet_v1 / Kad udp_packet_v1 dumps; default
    None keeps the plain build for existing callers.
    """

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("w", encoding="utf-8")
    return start_rust_client_with_output(repo, profile_dir, output_handle, features=features)


def start_rust_client_append(repo: Path, profile_dir: Path, output_path: Path) -> subprocess.Popen[str]:
    """Restarts `emulebb-rust` while appending to an existing harness log."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("a", encoding="utf-8")
    return start_rust_client_with_output(repo, profile_dir, output_handle)


def start_rust_client_executable(executable: Path, profile_dir: Path, output_path: Path) -> subprocess.Popen[str]:
    """Starts a staged `emulebb-rust` executable with a generated harness profile."""

    if not executable.is_file():
        raise RuntimeError(f"eMuleBB Rust executable was not found at '{executable}'.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_handle = output_path.open("w", encoding="utf-8")
    return start_rust_client_executable_with_output(executable, profile_dir, output_handle)


def spawn_rust_daemon(
    executable: Path,
    profile_dir: Path,
    *,
    output_handle,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    detached: bool = False,
    text: bool = True,
) -> subprocess.Popen:
    """Spawns the `emulebb-rust` daemon with the shared argv/stdio wiring.

    ``detached=True`` adds the Windows CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
    flags so the daemon outlives the launcher (used by the persistent soak restart
    controller); the default keeps it a managed child the launcher tears down.
    """

    creationflags = 0
    if detached and os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
    return subprocess.Popen(
        [str(executable), "--profile", str(profile_dir)],
        cwd=cwd if cwd is not None else executable.parent,
        env=env if env is not None else os.environ.copy(),
        stdout=output_handle,
        stderr=subprocess.STDOUT,
        text=text,
        creationflags=creationflags,
    )


def start_rust_client_executable_with_output(
    executable: Path,
    profile_dir: Path,
    output_handle,
) -> subprocess.Popen[str]:
    """Starts a staged `emulebb-rust` executable with an already-open output handle."""

    return spawn_rust_daemon(executable, profile_dir, output_handle=output_handle)


def start_rust_client_with_output(
    repo: Path, profile_dir: Path, output_handle, features: str | None = None
) -> subprocess.Popen[str]:
    """Starts `emulebb-rust` with an already-open output handle.

    ``features`` forwards a Cargo feature list (e.g. ``packet-diagnostics``);
    default None keeps the plain build.
    """

    feature_args = ["--features", features] if features else []
    return subprocess.Popen(
        [
            "cargo",
            "run",
            "-p",
            "emulebb-daemon",
            "--bin",
            "emulebb-rust",
            *feature_args,
            "--",
            "--profile",
            str(profile_dir),
        ],
        cwd=repo,
        env=rust_cargo_env(),
        stdout=output_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )


def stop_process_tree(process: subprocess.Popen | None, *, timeout_seconds: float = 10.0) -> None:
    """Stops a launched process and its children."""

    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        process.terminate()
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout_seconds)
