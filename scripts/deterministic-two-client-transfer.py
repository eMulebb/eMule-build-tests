"""Deterministic two-client eD2K transfer through the workspace ED2K server."""

from __future__ import annotations

import argparse
import itertools
import ipaddress
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import goed2k  # noqa: E402
from emule_test_harness.ini import read_ini_text  # noqa: E402
from emule_test_harness import windows_processes  # noqa: E402
from emule_test_harness.multi_client import CLIENT_IDENTITIES, resolve_harness_client  # noqa: E402
from emule_test_harness.script_modules import load_script_module  # noqa: E402


harness_cli_common = load_script_module("harness_cli_common", "harness-cli-common.py")
live_common = load_script_module("emule_live_profile_common", "emule-live-profile-common.py")
rest_smoke = load_script_module("rest_api_smoke", "rest-api-smoke.py")

SUITE_NAME = "deterministic-two-client-transfer"
API_KEY = "deterministic-two-client-transfer-key"
DEFAULT_FIXTURE_SIZE_BYTES = 132 * 1024 * 1024
DETERMINISTIC_BANDWIDTH_LIMIT_KIB = 262144
DETERMINISTIC_BANDWIDTH_CAPACITY_KIB = 327680
DETERMINISTIC_MAX_UPLOAD_CLIENTS = 32
ED2K_LOCAL_PORT_MIN = 20000
ED2K_LOCAL_PORT_MAX = 49151
ED2K_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")
SHARED_FILES_ROUTE = "/api/v1/shared-files"
CLIENT01 = CLIENT_IDENTITIES["emulebb"]
CLIENT02 = CLIENT_IDENTITIES["harness"]

SERVER_MET_HEADER = 0xE0
TAGTYPE_STRING = 0x02
ST_SERVERNAME = 0x01
ST_DYNIP = 0x85
ST_DESCRIPTION = 0x0B


class TransferCompletionTimeout(RuntimeError):
    """Raised when client1 never materializes the expected completed file."""

    def __init__(self, observations: list[dict[str, object]]) -> None:
        super().__init__("Timed out waiting for completed deterministic transfer file.")
        self.observations = observations


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parses the standalone deterministic transfer suite arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-root")
    parser.add_argument("--app-exe")
    parser.add_argument("--client2-app-exe")
    parser.add_argument("--profile-seed-dir")
    parser.add_argument("--artifacts-dir")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    parser.add_argument("--api-key", default=API_KEY)
    parser.add_argument("--lan-bind-addr", required=True)
    parser.add_argument("--p2p-bind-interface-name", default="")
    parser.add_argument("--p2p-bind-interface-address")
    parser.add_argument("--rest-ready-timeout-seconds", type=float, default=60.0)
    parser.add_argument("--server-connect-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--link-export-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--server-publish-timeout-seconds", type=float, default=180.0)
    parser.add_argument("--transfer-completion-timeout-seconds", type=float, default=900.0)
    parser.add_argument("--fixture-size-bytes", type=int, default=DEFAULT_FIXTURE_SIZE_BYTES)
    parser.add_argument("--ed2k-server-repo")
    parser.add_argument("--ed2k-server-exe")
    return parser.parse_args(argv)


def workspace_manifest_path(workspace_root: Path) -> Path:
    """Returns the generated workspace manifest path."""

    return workspace_root / "deps.json"


def resolve_manifest_repo(workspace_root: Path, repo_key: str) -> Path:
    """Resolves one repo path from the generated workspace manifest."""

    manifest_path = workspace_manifest_path(workspace_root)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    repos = payload.get("workspace", {}).get("repos", {})
    value = repos.get(repo_key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"Workspace manifest does not define workspace.repos.{repo_key}.")
    return (manifest_path.parent / value).resolve()


def resolve_client2_app_exe(workspace_root: Path, configuration: str, override: str | None) -> Path:
    """Resolves the MFC parity peer client executable."""

    availability = resolve_harness_client(workspace_root, configuration, override)
    if not availability.available or availability.executable is None:
        raise RuntimeError(f"Client2 MFC parity peer executable was not found: {availability.reason}.")
    return availability.executable


def is_port_available(port: int, *, host: str | None = None, udp: bool = False) -> bool:
    """Reports whether a TCP or UDP port can be bound locally."""

    bind_host = rest_smoke.require_lan_bind_addr(host)
    family = socket.AF_INET
    sock_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(family, sock_type) as probe:
        try:
            probe.bind((bind_host, port))
        except OSError:
            return False
    return True


def choose_tcp_port_with_udp_offset(lan_bind_addr: str | None = None, offset: int = 4) -> int:
    """Chooses a TCP port whose conventional ED2K UDP status port is free."""

    lan_bind_addr = rest_smoke.require_lan_bind_addr(lan_bind_addr, allow_env_fallback=True)
    max_tcp_port = min(ED2K_LOCAL_PORT_MAX, 65535 - offset)
    if ED2K_LOCAL_PORT_MIN > max_tcp_port:
        raise RuntimeError("ED2K local port scan range cannot fit the UDP offset.")
    start = random.randrange(ED2K_LOCAL_PORT_MIN, max_tcp_port + 1)
    candidates = itertools.chain(range(start, max_tcp_port + 1), range(ED2K_LOCAL_PORT_MIN, start))
    for port in candidates:
        if is_port_available(port, host=lan_bind_addr) and is_port_available(
            port + offset,
            host=lan_bind_addr,
            udp=True,
        ):
            return port
    raise RuntimeError("Could not allocate a TCP port with a free ED2K UDP offset.")


def choose_available_local_port(
    lan_bind_addr: str,
    used: set[int],
    *,
    udp: bool = False,
) -> int:
    """Chooses an unused local TCP/UDP port outside the Windows ephemeral range."""

    start = random.randrange(ED2K_LOCAL_PORT_MIN, ED2K_LOCAL_PORT_MAX + 1)
    candidates = itertools.chain(range(start, ED2K_LOCAL_PORT_MAX + 1), range(ED2K_LOCAL_PORT_MIN, start))
    for candidate in candidates:
        if candidate not in used and is_port_available(candidate, host=lan_bind_addr, udp=udp):
            return candidate
    raise RuntimeError("Could not allocate a local port in the ED2K harness range.")


def choose_distinct_ports(lan_bind_addr: str | None = None) -> dict[str, int]:
    """Allocates the suite's local ports without intentional reuse."""

    ports: dict[str, int] = {}
    used: set[int] = set()

    def add(name: str, value: int) -> None:
        if value in used:
            raise RuntimeError(f"Port allocation collision for {name}: {value}")
        used.add(value)
        ports[name] = value

    lan_bind_addr = rest_smoke.require_lan_bind_addr(lan_bind_addr, allow_env_fallback=True)
    ed2k_tcp = choose_tcp_port_with_udp_offset(lan_bind_addr)
    add("ed2k_tcp", ed2k_tcp)
    add("ed2k_udp", ed2k_tcp + 4)
    for name in (
        "ed2k_admin",
        "client1_rest",
        "client2_rest",
        "client1_tcp",
        "client1_udp",
        "client2_tcp",
        "client2_udp",
    ):
        try:
            add(name, choose_available_local_port(lan_bind_addr, used, udp=name.endswith("_udp")))
        except RuntimeError as exc:
            raise RuntimeError(f"Could not allocate port for {name}.") from exc
    return ports


def write_server_met(path: Path, *, address: str, port: int, name: str) -> None:
    """Writes a minimal eMule-compatible `server.met` containing one local server."""

    if not 0 < port <= 65535:
        raise ValueError("Server port must be in the range 1..65535.")
    ip_bytes = ipaddress.IPv4Address(address).packed
    path.parent.mkdir(parents=True, exist_ok=True)
    tags = [
        build_old_ed2k_string_tag(ST_SERVERNAME, name),
        build_old_ed2k_string_tag(ST_DYNIP, address),
        build_old_ed2k_string_tag(ST_DESCRIPTION, "workspace deterministic ED2K server"),
    ]
    payload = bytearray()
    payload.extend(struct.pack("<BI", SERVER_MET_HEADER, 1))
    payload.extend(ip_bytes)
    payload.extend(struct.pack("<HI", port, len(tags)))
    for tag in tags:
        payload.extend(tag)
    path.write_bytes(bytes(payload))


def build_old_ed2k_string_tag(name_id: int, value: str) -> bytes:
    """Builds one old-style eD2K string tag as stored in `server.met`."""

    encoded = value.encode("mbcs" if os.name == "nt" else "utf-8")
    if len(encoded) > 0xFFFF:
        raise ValueError("server.met tag string is too long.")
    return struct.pack("<BHBH", TAGTYPE_STRING, 1, name_id, len(encoded)) + encoded


def parse_ed2k_file_link(link: str) -> dict[str, object]:
    """Parses the deterministic eD2K file link exported by client2."""

    parts = link.strip().split("|")
    if len(parts) < 6 or parts[0] != "ed2k://" or parts[1] != "file":
        raise ValueError(f"Unsupported eD2K file link: {link!r}")
    name = parts[2]
    size = int(parts[3])
    file_hash = parts[4].lower()
    if not ED2K_HASH_PATTERN.match(file_hash):
        raise ValueError(f"Invalid eD2K hash in exported link: {file_hash!r}")
    return {"name": name, "size": size, "hash": file_hash}


def extract_ed2k_link(body: dict[str, object]) -> str | None:
    """Returns the first eD2K file link from accepted REST response shapes."""

    for key in ("link", "ed2kLink"):
        value = body.get(key)
        if isinstance(value, str) and value.startswith("ed2k://|file|"):
            return value
    for key in ("links", "ed2kLinks"):
        value = body.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.startswith("ed2k://|file|"):
                    return item
    return None


def shared_file_row_ed2k_link(row: dict[str, object], *, file_name: str, file_hash: str) -> str | None:
    """Builds an eD2K link from a published shared-file row when the route cannot."""

    if row.get("publishedEd2k") is False:
        return None
    size = row.get("sizeBytes", row.get("size"))
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        return None
    quoted_name = urllib.parse.quote(file_name, safe="")
    return f"ed2k://|file|{quoted_name}|{size}|{file_hash}|/"


def response_payload(result: dict[str, object], expected_status: int) -> object:
    """Returns a REST payload without requiring harness-wide smoke assertions."""

    if int(result.get("status", 0)) != expected_status:
        raise AssertionError(rest_smoke.compact_http_result(result))
    raw = result.get("raw_json")
    if isinstance(raw, dict) and "data" in raw and "meta" in raw:
        return raw["data"]
    return result.get("json")


def rows_from_result(result: dict[str, object]) -> list[object]:
    """Extracts REST rows from either a raw array or paged envelope."""

    payload = response_payload(result, 200)
    if isinstance(payload, dict) and isinstance(payload.get("items"), list):
        return list(payload["items"])
    if isinstance(payload, list):
        return list(payload)
    raise AssertionError(rest_smoke.compact_http_result(result))


def ed2k_link_body_from_result(result: dict[str, object]) -> dict[str, object]:
    """Extracts an eD2K link route object from a successful REST response."""

    payload = response_payload(result, 200)
    if isinstance(payload, dict):
        return payload
    raise AssertionError(rest_smoke.compact_http_result(result))


def write_fixture_file(path: Path, size_bytes: int, *, seed: int = 0xED2B2026) -> str:
    """Writes deterministic low-compressibility bytes and returns the SHA-256 proof hash."""

    if size_bytes <= 0:
        raise ValueError("Fixture size must be greater than zero.")
    path.parent.mkdir(parents=True, exist_ok=True)
    import random
    remaining = size_bytes
    import hashlib

    digest = hashlib.sha256()
    rng = random.Random(seed)
    with path.open("wb") as handle:
        while remaining > 0:
            chunk_size = min(64 * 1024, remaining)
            chunk = bytes(rng.getrandbits(8) for _ in range(chunk_size))
            handle.write(chunk)
            digest.update(chunk)
            remaining -= chunk_size
    return digest.hexdigest()


def file_sha256(path: Path) -> str:
    """Returns one file's SHA-256 hex digest."""

    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wait_for_exported_link(path: Path, timeout_seconds: float) -> str:
    """Waits for client2 to export a non-empty eD2K link file."""

    def resolve():
        if not path.is_file():
            return None
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        return text if text.startswith("ed2k://|file|") else None

    return live_common.wait_for(resolve, timeout_seconds, 1.0, "client2 exported eD2K link")


def add_emule_shared_file(base_url: str, api_key: str, file_path: Path) -> dict[str, object]:
    """Adds one eMuleBB seed file to the shared-file model through REST."""

    result = rest_smoke.http_request(
        base_url,
        SHARED_FILES_ROUTE,
        method="POST",
        api_key=api_key,
        json_body={"path": str(file_path.resolve())},
        request_timeout_seconds=30.0,
    )
    if int(result.get("status", 0)) != 200:
        raise RuntimeError(f"Adding eMuleBB shared file failed: {rest_smoke.compact_http_result(result)!r}")
    return rest_smoke.compact_http_result(result)


def reload_emule_shared_files(base_url: str, api_key: str) -> dict[str, object]:
    """Requests a native eMuleBB shared-files reload through REST."""

    result = rest_smoke.http_request(
        base_url,
        f"{SHARED_FILES_ROUTE}/operations/reload",
        method="POST",
        api_key=api_key,
        json_body={},
        request_timeout_seconds=30.0,
    )
    if int(result.get("status", 0)) != 200:
        raise RuntimeError(f"Reloading eMuleBB shared files failed: {rest_smoke.compact_http_result(result)!r}")
    return rest_smoke.compact_http_result(result)


def wait_for_emule_shared_file_link(
    base_url: str,
    api_key: str,
    *,
    file_name: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits until eMuleBB exposes a shared-file row and ED2K link for one file."""

    observations: list[dict[str, object]] = []

    def resolve():
        rows_result = rest_smoke.http_request(
            base_url,
            f"{SHARED_FILES_ROUTE}?offset=0&limit=100",
            api_key=api_key,
            request_timeout_seconds=10.0,
        )
        try:
            rows = rows_from_result(rows_result)
        except Exception as exc:
            observations.append(
                {
                    "error": type(exc).__name__,
                    "result": rest_smoke.compact_http_result(rows_result),
                    "observed_at": round(time.time(), 3),
                }
            )
            raise
        observations.append({"count": len(rows), "observed_at": round(time.time(), 3)})
        for row in rows:
            if not isinstance(row, dict) or row.get("name") != file_name:
                continue
            file_hash = row.get("hash")
            if not isinstance(file_hash, str) or not ED2K_HASH_PATTERN.match(file_hash):
                continue
            normalized_hash = file_hash.lower()
            link_result = rest_smoke.http_request(
                base_url,
                f"{SHARED_FILES_ROUTE}/{normalized_hash}/ed2k-link",
                api_key=api_key,
                request_timeout_seconds=10.0,
            )
            link_observation: dict[str, object] = {
                "count": len(rows),
                "hash": normalized_hash,
                "observed_at": round(time.time(), 3),
            }
            try:
                body = ed2k_link_body_from_result(link_result)
                link = extract_ed2k_link(body)
                if link is None:
                    link_observation["link_error"] = "missing_ed2k_link"
                    link_observation["link_body"] = body
                else:
                    link_observation["link_source"] = "route"
            except Exception as exc:
                link = None
                link_observation["link_error"] = type(exc).__name__
                link_observation["link_result"] = rest_smoke.compact_http_result(link_result)
            if link is None:
                link = shared_file_row_ed2k_link(row, file_name=file_name, file_hash=normalized_hash)
                if link is not None:
                    link_observation["link_source"] = "shared_file_row"
            observations.append(link_observation)
            if link is not None:
                return {
                    "file": dict(row),
                    "hash": normalized_hash,
                    "link": link,
                    "observations": observations[-20:],
                }
        return None

    try:
        return live_common.wait_for(resolve, timeout_seconds, 1.0, f"eMuleBB shared link for {file_name}")
    except Exception as exc:
        raise RuntimeError(f"Timed out waiting for eMuleBB shared link. Observations: {observations[-20:]!r}") from exc


def wait_for_file(path: Path, timeout_seconds: float, description: str) -> dict[str, object]:
    """Waits for a file artifact to be created."""

    def resolve():
        if not path.is_file():
            return None
        return {
            "path": str(path),
            "size": path.stat().st_size,
        }

    return live_common.wait_for(resolve, timeout_seconds, 0.5, description)


def compact_transfer_http(result: dict[str, object]) -> dict[str, object]:
    """Returns a compact REST result while preserving transfer JSON payloads for diagnostics."""

    compact: dict[str, object] = {
        "status": int(result["status"]),
        "content_type": result.get("content_type"),
    }
    payload = result.get("json")
    if isinstance(payload, dict):
        compact["json"] = payload
    elif isinstance(payload, list):
        compact["json"] = payload
    elif isinstance(result.get("body_text"), str):
        compact["body_text"] = str(result["body_text"])[:2000]
    return compact


def snapshot_file(path: Path, *, hash_limit_bytes: int) -> dict[str, object]:
    """Returns stable filesystem state for one path without reading very large files by accident."""

    if not path.exists():
        return {"path": str(path), "exists": False}
    stat = path.stat()
    snapshot: dict[str, object] = {
        "path": str(path),
        "exists": True,
        "is_file": path.is_file(),
        "size": stat.st_size,
        "last_write_time": stat.st_mtime,
    }
    if path.is_file() and stat.st_size <= hash_limit_bytes:
        snapshot["sha256"] = file_sha256(path)
    return snapshot


def snapshot_directory(path: Path, *, hash_limit_bytes: int) -> list[dict[str, object]]:
    """Returns a deterministic shallow file listing for one directory."""

    if not path.is_dir():
        return []
    rows = [snapshot_file(child, hash_limit_bytes=hash_limit_bytes) for child in sorted(path.iterdir(), key=lambda item: item.name.lower())]
    return rows


def collect_client1_transfer_snapshot(
    *,
    base_url: str,
    api_key: str,
    transfer_hash: str,
    incoming_path: Path,
    temp_dir: Path,
    hash_limit_bytes: int,
) -> dict[str, object]:
    """Collects REST and filesystem state for a live client1 transfer."""

    snapshot: dict[str, object] = {
        "observed_at": round(time.time(), 3),
        "incoming_file": snapshot_file(incoming_path, hash_limit_bytes=hash_limit_bytes),
        "incoming_dir": snapshot_directory(incoming_path.parent, hash_limit_bytes=hash_limit_bytes),
        "temp_dir": snapshot_directory(temp_dir, hash_limit_bytes=hash_limit_bytes),
    }
    endpoints = {
        "transfer": f"/api/v1/transfers/{transfer_hash}",
        "details": f"/api/v1/transfers/{transfer_hash}/details",
        "sources": f"/api/v1/transfers/{transfer_hash}/sources",
    }
    for name, endpoint in endpoints.items():
        try:
            snapshot[name] = compact_transfer_http(
                rest_smoke.http_request(base_url, endpoint, api_key=api_key, request_timeout_seconds=10.0)
            )
        except Exception as exc:
            snapshot[name] = {"error_type": type(exc).__name__, "error_message": str(exc) or repr(exc)}
    return snapshot


def wait_for_completed_file(
    path: Path,
    *,
    expected_size: int,
    expected_sha256: str,
    timeout_seconds: float,
    snapshot_callback=None,
) -> dict[str, object]:
    """Waits until client1 completes the transferred file with exact bytes."""

    observations: list[dict[str, object]] = []
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        if not path.is_file():
            row: dict[str, object] = {"exists": False, "observed_at": round(time.time(), 3)}
        else:
            size = path.stat().st_size
            row = {"exists": True, "size": size, "observed_at": round(time.time(), 3)}
            if size == expected_size:
                digest = file_sha256(path)
                row["sha256"] = digest
                if digest == expected_sha256:
                    row["observations"] = observations[-20:]
                    return row
        if snapshot_callback is not None:
            row["snapshot"] = snapshot_callback()
        observations.append(row)
        time.sleep(1.0)

    final_row: dict[str, object] = {"exists": path.is_file(), "observed_at": round(time.time(), 3)}
    if path.is_file():
        final_row["size"] = path.stat().st_size
        if final_row["size"] == expected_size:
            final_row["sha256"] = file_sha256(path)
    if snapshot_callback is not None:
        final_row["snapshot"] = snapshot_callback()
    observations.append(final_row)
    raise TransferCompletionTimeout(observations[-20:])


def discover_interface_ipv4(interface_name: str) -> str:
    """Finds an IPv4 address for a named interface or the first usable LAN interface."""

    candidates: set[ipaddress.IPv4Address] = set()
    if os.name == "nt":
        try:
            for value in windows_processes.collect_adapter_ipv4_addresses(interface_name):
                candidates.add(ipaddress.IPv4Address(value))
        except Exception as exc:
            if interface_name.strip():
                raise RuntimeError(
                    f"Could not query Windows adapter IPv4 addresses for interface {interface_name!r}. "
                    "Pass --p2p-bind-interface-address to the suite if automatic discovery is unsuitable."
                ) from exc
    if not interface_name.strip():
        for host in {socket.gethostname(), socket.getfqdn()}:
            try:
                for family, _, _, _, sockaddr in socket.getaddrinfo(host, None, socket.AF_INET):
                    if family == socket.AF_INET and sockaddr:
                        candidates.add(ipaddress.IPv4Address(str(sockaddr[0])))
            except OSError:
                continue
    usable = [address for address in candidates if not (address.is_loopback or address.is_link_local or address.is_unspecified)]
    if not usable:
        target = f"interface {interface_name!r}" if interface_name.strip() else "a usable non-loopback LAN interface"
        raise RuntimeError(
            f"Could not discover IPv4 address for {target}. "
            "Pass --p2p-bind-interface-address to the suite if automatic discovery is unsuitable."
        )
    usable.sort(key=lambda address: (0 if str(address).startswith("192.") else 1, 0 if address.is_private else 1, str(address)))
    return str(usable[0])


def resolve_lan_p2p_bind_address(
    *,
    lan_bind_addr: str,
    p2p_bind_interface_name: str = "",
    p2p_bind_interface_address: str | None = None,
) -> str:
    """Returns the P2P bind address for LAN/local tests.

    LAN campaigns default P2P address binding to the same explicit LAN address
    used for REST/control. Interface discovery is only used when the caller
    deliberately supplies an interface name.
    """

    explicit_address = str(p2p_bind_interface_address or "").strip()
    if explicit_address:
        return rest_smoke.require_lan_bind_addr(explicit_address, option_name="--p2p-bind-interface-address")
    interface_name = str(p2p_bind_interface_name or "").strip()
    if interface_name:
        return discover_interface_ipv4(interface_name)
    return rest_smoke.require_lan_bind_addr(lan_bind_addr)


def configure_client_profile(
    *,
    config_dir: Path,
    app_exe: Path,
    nick: str,
    tcp_port: int,
    udp_port: int,
    ed2k_enabled: bool,
    autoconnect: bool,
    rest_api_key: str | None = None,
    rest_port: int | None = None,
    lan_bind_addr: str = "",
    p2p_bind_interface_name: str = "",
    p2p_bind_addr: str = "",
    crypt_layer_supported: bool | None = None,
    crypt_layer_requested: bool | None = None,
    crypt_layer_required: bool | None = None,
    crypt_tcp_padding_length: int | None = None,
) -> None:
    """Applies deterministic network and optional REST settings to one profile."""

    bind_interface = p2p_bind_interface_name.strip()
    effective_p2p_bind_addr = "" if bind_interface else p2p_bind_addr.strip()
    values: list[tuple[str, str]] = [
            ("Nick", nick),
            ("Port", str(tcp_port)),
            ("UDPPort", str(udp_port)),
            ("ServerUDPPort", "65535"),
            ("ConfirmExit", "0"),
            ("Autoconnect", "1" if autoconnect else "0"),
            ("Reconnect", "0"),
            ("NetworkED2K", "1" if ed2k_enabled else "0"),
            ("NetworkKademlia", "0"),
            ("AutoConnectStaticOnly", "0"),
            ("SafeServerConnect", "0"),
            ("FilterBadIPs", "0"),
            ("AllowLocalHostIP", "1"),
            ("GeoLocationLookupEnabled", "0"),
            ("IPFilterEnabled", "0"),
            ("DownloadCapacity", str(DETERMINISTIC_BANDWIDTH_CAPACITY_KIB)),
            ("UploadCapacity", str(DETERMINISTIC_BANDWIDTH_CAPACITY_KIB)),
            ("UploadCapacityNew", str(DETERMINISTIC_BANDWIDTH_CAPACITY_KIB)),
            ("MaxUpload", str(DETERMINISTIC_BANDWIDTH_LIMIT_KIB)),
            ("MaxDownload", str(DETERMINISTIC_BANDWIDTH_LIMIT_KIB)),
            ("CommitFiles", "2"),
            ("FileBufferSize", "16384"),
            ("FileBufferTimeLimit", "1"),
            ("AllocateFullFile", "0"),
            ("SparsePartFiles", "0"),
            ("CloseUPnPOnExit", "0"),
            ("SaveLogToDisk", "1"),
            ("SaveDebugToDisk", "1"),
            ("VerboseOptions", "1"),
            ("Verbose", "1"),
            ("FullVerbose", "1"),
            ("MaxLogFileSize", "10485760"),
            ("MaxLogBuff", "256"),
            ("LogFileFormat", "0"),
            ("BindInterface", bind_interface),
            ("BindAddr", effective_p2p_bind_addr),
            ("BlockNetworkWhenBindUnavailableAtStartup", "1" if bind_interface or effective_p2p_bind_addr else "0"),
    ]
    if crypt_layer_supported is not None:
        values.append(("CryptLayerSupported", "1" if crypt_layer_supported else "0"))
    if crypt_layer_requested is not None:
        values.append(("CryptLayerRequested", "1" if crypt_layer_requested else "0"))
    if crypt_layer_required is not None:
        values.append(("CryptLayerRequired", "1" if crypt_layer_required else "0"))
    if crypt_tcp_padding_length is not None:
        values.append(("CryptTCPPaddingLength", str(crypt_tcp_padding_length)))
    live_common.apply_emule_preferences(config_dir, tuple(values))
    live_common.apply_section_preferences(
        config_dir,
        "UploadPolicy",
        (("MaxUploadClientsAllowed", str(DETERMINISTIC_MAX_UPLOAD_CLIENTS)),),
    )
    live_common.apply_section_preferences(
        config_dir,
        "UPnP",
        (("EnableUPnP", "0"),),
    )
    if rest_api_key is not None and rest_port is not None:
        live_common.apply_webserver_profile(
            config_dir,
            live_common.WebServerProfileSpec(
                app_exe=app_exe,
                api_key=rest_api_key,
                port=rest_port,
                lan_bind_addr=rest_smoke.require_lan_bind_addr(lan_bind_addr),
            ),
        )


def retry_rest_request(
    base_url: str,
    path: str,
    *,
    api_key: str,
    timeout_seconds: float,
    request_timeout_seconds: float = 30.0,
    **kwargs,
) -> dict[str, object]:
    """Retries transient REST socket failures during live client startup."""

    observations: list[dict[str, object]] = []

    def resolve():
        try:
            result = rest_smoke.http_request(
                base_url,
                path,
                api_key=api_key,
                request_timeout_seconds=request_timeout_seconds,
                **kwargs,
            )
        except (OSError, TimeoutError, urllib.error.URLError) as exc:
            observations.append(
                {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "observed_at": round(time.time(), 3),
                }
            )
            return None
        if observations:
            result = dict(result)
            result["transient_errors"] = observations[-5:]
        return result

    try:
        return live_common.wait_for(resolve, timeout_seconds, 0.5, f"REST request {path}")
    except RuntimeError as exc:
        raise RuntimeError(f"{exc}. REST transient observations: {observations[-5:]}") from exc


def add_and_connect_server(base_url: str, api_key: str, *, address: str, port: int, timeout_seconds: float) -> dict[str, object]:
    """Ensures the local ED2K server exists and waits until eMule connects to it."""

    server = {"address": address, "port": port, "name": "emulebb-local-e2e"}
    servers_result = retry_rest_request(
        base_url,
        "/api/v1/servers",
        api_key=api_key,
        timeout_seconds=timeout_seconds,
    )
    server_rows = rows_from_result(servers_result)
    matching_rows = [
        row
        for row in server_rows
        if isinstance(row, dict)
        and str(row.get("address") or "").lower() == address.lower()
        and int(row.get("port") or 0) == port
    ]
    add_summary: dict[str, object]
    if matching_rows:
        add_summary = {"preloaded": True, "server": dict(matching_rows[0])}
    else:
        add_result = retry_rest_request(
            base_url,
            "/api/v1/servers",
            method="POST",
            api_key=api_key,
            json_body=server,
            timeout_seconds=timeout_seconds,
        )
        if int(add_result.get("status", 0)) != 200:
            raise RuntimeError(f"Adding local ED2K server failed: {rest_smoke.compact_http_result(add_result)!r}")
        rest_smoke.require_json_object(add_result, 200)
        add_summary = rest_smoke.compact_http_result(add_result)

    connect_result = retry_rest_request(
        base_url,
        f"/api/v1/servers/{address}:{port}/operations/connect",
        method="POST",
        api_key=api_key,
        json_body={},
        timeout_seconds=timeout_seconds,
    )
    if int(connect_result.get("status", 0)) != 200:
        raise RuntimeError(f"Connecting local ED2K server failed: {rest_smoke.compact_http_result(connect_result)!r}")
    connect_summary = rest_smoke.compact_http_result(connect_result)
    connect_payload = response_payload(connect_result, 200)
    if not isinstance(connect_payload, dict):
        raise RuntimeError(f"Connecting local ED2K server returned a non-object payload: {connect_summary!r}")
    connected = wait_for_emule_server_connected(
        base_url,
        api_key,
        expected_server=server,
        timeout_seconds=timeout_seconds,
    )
    return {
        "server": server,
        "servers_before_connect": rest_smoke.compact_http_result(servers_result),
        "add": add_summary,
        "connect": connect_summary,
        "connected": connected,
    }


def wait_for_emule_server_connected(
    base_url: str,
    api_key: str,
    *,
    expected_server: dict[str, object],
    timeout_seconds: float,
) -> dict[str, object]:
    """Waits for the deterministic ED2K server while preserving poll observations."""

    observations: list[dict[str, object]] = []
    expected_address = str(expected_server.get("address") or "").lower()
    expected_port = int(expected_server.get("port") or 0)

    def resolve():
        result = rest_smoke.http_request(
            base_url,
            "/api/v1/status",
            api_key=api_key,
            request_timeout_seconds=10.0,
        )
        try:
            payload = response_payload(result, 200)
        except Exception as exc:
            observations.append(
                {
                    "error": type(exc).__name__,
                    "result": rest_smoke.compact_http_result(result),
                    "observed_at": round(time.time(), 3),
                }
            )
            return None
        if not isinstance(payload, dict):
            observations.append(
                {
                    "error": "non_object_payload",
                    "result": rest_smoke.compact_http_result(result),
                    "observed_at": round(time.time(), 3),
                }
            )
            return None

        status_payload = rest_smoke.get_server_status_payload(payload)
        snapshot = rest_smoke.compact_server_status(status_payload)
        snapshot["observed_at"] = round(time.time(), 3)
        observations.append(snapshot)

        current_server = status_payload.get("currentServer")
        matches_expected = False
        if isinstance(current_server, dict):
            matches_expected = (
                str(current_server.get("address") or "").lower() == expected_address
                and int(current_server.get("port") or 0) == expected_port
            )
        if status_payload.get("connected") and matches_expected:
            return {
                "status": rest_smoke.compact_http_result(result),
                "observations": observations[-30:],
            }
        return None

    try:
        return live_common.wait_for(resolve, timeout_seconds, 1.0, "deterministic ED2K server connected state")
    except RuntimeError as exc:
        raise RuntimeError(
            f"Timed out waiting for deterministic ED2K server connection. Observations: {observations[-30:]!r}"
        ) from exc


def add_transfer(base_url: str, api_key: str, link: str, transfer_hash: str) -> dict[str, object]:
    """Queues the exported eD2K link in client1 through REST."""

    result = rest_smoke.http_request(
        base_url,
        "/api/v1/transfers",
        method="POST",
        api_key=api_key,
        json_body={"link": link, "paused": False, "categoryId": 0},
        request_timeout_seconds=30.0,
    )
    summary = rest_smoke.compact_http_result(result)
    payload = response_payload(result, 200)
    rows = (payload.get("items") or payload.get("results")) if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows:
        raise AssertionError(summary)
    item = rows[0]
    if not isinstance(item, dict) or item.get("ok") is not True or str(item.get("hash") or "").lower() != transfer_hash.lower():
        raise AssertionError(summary)
    return {"response": summary, "item": item}


def read_preferences_snapshot(config_dir: Path) -> dict[str, object]:
    """Returns the bind and port preferences that matter for this suite."""

    text = read_ini_text(config_dir / "preferences.ini")
    keys = (
        "Nick",
        "Port",
        "UDPPort",
        "BindInterface",
        "BindAddr",
        "Autoconnect",
        "NetworkED2K",
        "NetworkKademlia",
        "DownloadCapacity",
        "UploadCapacity",
        "UploadCapacityNew",
        "MaxUpload",
        "MaxDownload",
        "MaxUploadClientsAllowed",
        "CryptLayerSupported",
        "CryptLayerRequested",
        "CryptLayerRequired",
        "CryptTCPPaddingLength",
    )
    snapshot: dict[str, object] = {}
    for key in keys:
        match = re.search(rf"(?im)^{re.escape(key)}=(.*)$", text)
        snapshot[key] = match.group(1).strip() if match else None
    return snapshot


def main(argv: list[str] | None = None) -> int:
    """Runs the deterministic two-client transfer suite."""

    args = parse_args(argv)
    paths = harness_cli_common.prepare_run_paths(
        script_file=__file__,
        suite_name=SUITE_NAME,
        configuration=args.configuration,
        workspace_root=None,
        app_root=args.app_root,
        app_exe=args.app_exe,
        artifacts_dir=args.artifacts_dir,
        keep_artifacts=args.keep_artifacts,
    )
    profile_seed_dir = Path(args.profile_seed_dir).resolve() if args.profile_seed_dir else paths.seed_config_dir
    report: dict[str, object] = {
        "suite": SUITE_NAME,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "checks": {},
    }
    server_process: subprocess.Popen | None = None
    client1_app = None
    client2_app = None
    current_phase = "initializing"

    try:
        p2p_address = resolve_lan_p2p_bind_address(
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
            p2p_bind_interface_address=args.p2p_bind_interface_address,
        )
        ports = choose_distinct_ports(args.lan_bind_addr)
        report["network"] = {
            "p2p_bind_interface_name": args.p2p_bind_interface_name,
            "p2p_bind_interface_address": p2p_address,
            "ports": ports,
        }

        server_dir = paths.source_artifacts_dir / "ed2k-server"
        current_phase = "start_ed2k_server"
        ed2k_server = goed2k.launch_ed2k_server(
            workspace_root=paths.workspace_root,
            server_dir=server_dir,
            ed2k_port=ports["ed2k_tcp"],
            admin_port=ports["ed2k_admin"],
            token=args.api_key,
            admin_address=args.lan_bind_addr,
            ed2k_address=p2p_address,
            repo_override=args.ed2k_server_repo,
            exe_override=args.ed2k_server_exe,
        )
        server_process = ed2k_server.process
        admin_base_url = ed2k_server.admin_base_url
        report["checks"]["server_build"] = ed2k_server.build
        report["checks"]["ed2k_server_health"] = ed2k_server.health
        report["ed2k_server"] = ed2k_server.config

        fixture_dir = paths.source_artifacts_dir / "client2-shared"
        fixture_file = fixture_dir / "deterministic-two-client-transfer.bin"
        fixture_sha256 = write_fixture_file(fixture_file, args.fixture_size_bytes)
        report["fixture"] = {
            "path": str(fixture_file),
            "name": fixture_file.name,
            "size": args.fixture_size_bytes,
            "sha256": fixture_sha256,
        }

        client1 = live_common.prepare_scenario_profile(
            profile_seed_dir,
            paths.source_artifacts_dir,
            [],
            CLIENT01.profile_id,
        )
        client2 = live_common.prepare_scenario_profile(
            profile_seed_dir,
            paths.source_artifacts_dir,
            [],
            CLIENT02.profile_id,
        )
        client2_app_exe = resolve_client2_app_exe(paths.workspace_root, args.configuration, args.client2_app_exe)
        configure_client_profile(
            config_dir=Path(client1["config_dir"]),
            app_exe=paths.app_exe,
            nick=CLIENT01.nick,
            tcp_port=ports["client1_tcp"],
            udp_port=ports["client1_udp"],
            ed2k_enabled=True,
            autoconnect=False,
            rest_api_key=args.api_key,
            rest_port=ports["client1_rest"],
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
        )
        configure_client_profile(
            config_dir=Path(client2["config_dir"]),
            app_exe=client2_app_exe,
            nick=CLIENT02.nick,
            tcp_port=ports["client2_tcp"],
            udp_port=ports["client2_udp"],
            ed2k_enabled=True,
            autoconnect=True,
            rest_api_key=args.api_key,
            rest_port=ports["client2_rest"],
            lan_bind_addr=args.lan_bind_addr,
            p2p_bind_interface_name=args.p2p_bind_interface_name,
        )
        for profile in (client1, client2):
            write_server_met(
                Path(profile["config_dir"]) / "server.met",
                address=p2p_address,
                port=ports["ed2k_tcp"],
                name="emulebb-local-e2e",
            )

        report["profiles"] = {
            CLIENT01.profile_id: {
                "client_key": CLIENT01.key,
                "nick": CLIENT01.nick,
                "profile_base": str(client1["profile_base"]),
                "config_dir": str(client1["config_dir"]),
                "incoming_dir": str(client1["incoming_dir"]),
                "temp_dir": str(client1["temp_dir"]),
                "preferences": read_preferences_snapshot(Path(client1["config_dir"])),
            },
            CLIENT02.profile_id: {
                "client_key": CLIENT02.key,
                "nick": CLIENT02.nick,
                "profile_base": str(client2["profile_base"]),
                "config_dir": str(client2["config_dir"]),
                "incoming_dir": str(client2["incoming_dir"]),
                "temp_dir": str(client2["temp_dir"]),
                "app_exe": str(client2_app_exe),
                "preferences": read_preferences_snapshot(Path(client2["config_dir"])),
            },
        }

        current_phase = "launch_client2"
        client2_app = live_common.launch_app(
            client2_app_exe,
            Path(client2["profile_base"]),
            minimized_to_tray=True,
        )
        client2_base_url = f"http://{args.lan_bind_addr}:{ports['client2_rest']}"
        report["checks"]["client2_rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(client2_base_url, args.api_key, args.rest_ready_timeout_seconds)
        )
        report["checks"]["client2_shared_file_add"] = add_emule_shared_file(client2_base_url, args.api_key, fixture_file)
        report["checks"]["client2_shared_files_reload"] = reload_emule_shared_files(client2_base_url, args.api_key)
        shared_link = wait_for_emule_shared_file_link(
            client2_base_url,
            args.api_key,
            file_name=fixture_file.name,
            timeout_seconds=args.link_export_timeout_seconds,
        )
        exported_link = str(shared_link["link"])
        link_info = parse_ed2k_file_link(exported_link)
        report["checks"]["client2_shared_file_link"] = {**shared_link, "parsed": link_info}
        transfer_hash = str(link_info["hash"])
        report["checks"]["client2_server_client"] = goed2k.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT02.nick,
            args.server_connect_timeout_seconds,
        )
        report["checks"]["client2_server_file"] = goed2k.wait_for_server_file(
            admin_base_url,
            args.api_key,
            transfer_hash,
            args.server_publish_timeout_seconds,
        )

        current_phase = "launch_client1"
        client1_app = live_common.launch_app(paths.app_exe, Path(client1["profile_base"]), minimized_to_tray=True)
        base_url = f"http://{args.lan_bind_addr}:{ports['client1_rest']}"
        report["checks"]["client1_rest_ready"] = rest_smoke.compact_http_result(
            rest_smoke.wait_for_rest_ready(base_url, args.api_key, args.rest_ready_timeout_seconds)
        )
        current_phase = "client1_server_connect"
        report["checks"]["client1_server_connect"] = add_and_connect_server(
            base_url,
            args.api_key,
            address=p2p_address,
            port=ports["ed2k_tcp"],
            timeout_seconds=args.server_connect_timeout_seconds,
        )
        report["checks"]["client1_server_client"] = goed2k.wait_for_server_client(
            admin_base_url,
            args.api_key,
            CLIENT01.nick,
            args.server_connect_timeout_seconds,
        )

        current_phase = "add_transfer"
        report["checks"]["client1_transfer_add"] = add_transfer(base_url, args.api_key, exported_link, transfer_hash)
        completed_path = Path(client1["incoming_dir"]) / str(link_info["name"])
        report["checks"]["client1_transfer_completed_file"] = wait_for_completed_file(
            completed_path,
            expected_size=int(link_info["size"]),
            expected_sha256=fixture_sha256,
            timeout_seconds=args.transfer_completion_timeout_seconds,
            snapshot_callback=lambda: collect_client1_transfer_snapshot(
                base_url=base_url,
                api_key=args.api_key,
                transfer_hash=transfer_hash,
                incoming_path=completed_path,
                temp_dir=Path(client1["temp_dir"]),
                hash_limit_bytes=max(int(link_info["size"]), args.fixture_size_bytes),
            ),
        )
        final_transfer = rest_smoke.http_request(base_url, f"/api/v1/transfers/{transfer_hash}", api_key=args.api_key)
        report["checks"]["client1_transfer_final_rest"] = compact_transfer_http(final_transfer)
        report["checks"]["ed2k_server_stats_final"] = goed2k.admin_request(admin_base_url, args.api_key, "/api/stats")
        report["status"] = "passed"
        return 0
    except Exception as exc:
        report["status"] = "failed"
        report["current_phase"] = current_phase
        report["error"] = {"type": type(exc).__name__, "message": str(exc) or repr(exc)}
        if isinstance(exc, TransferCompletionTimeout):
            report["checks"]["client1_transfer_completion_timeout"] = {"observations": exc.observations}
        return 1
    finally:
        close_results: dict[str, object] = {}
        for name, app in ((CLIENT01.profile_id, client1_app), (CLIENT02.profile_id, client2_app)):
            if app is None:
                continue
            try:
                live_common.close_app_cleanly(app)
                close_results[name] = {"ok": True}
            except Exception as exc:
                close_results[name] = {"ok": False, "type": type(exc).__name__, "message": str(exc)}
        goed2k.stop_process(server_process)
        report["cleanup"] = close_results
        report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        report_path = paths.source_artifacts_dir / "deterministic-two-client-transfer-result.json"
        harness_cli_common.write_json_file(report_path, report)
        try:
            harness_cli_common.publish_run_artifacts(paths)
            harness_cli_common.publish_latest_report(paths)
        finally:
            harness_cli_common.cleanup_source_artifacts(paths)


if __name__ == "__main__":
    raise SystemExit(main())
