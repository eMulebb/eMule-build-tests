from __future__ import annotations

import importlib.util
import json
import re
import struct
import sys
from pathlib import Path

import pytest

from emule_test_harness import goed2k


def load_suite_module():
    """Loads the hyphenated deterministic transfer script for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "deterministic-two-client-transfer.py"
    spec = importlib.util.spec_from_file_location("deterministic_two_client_transfer_test_module", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_script_module(filename: str, module_name: str):
    """Loads one hyphenated script by filename for unit tests."""

    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / filename
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_resolve_manifest_repo_uses_workspace_deps(tmp_path: Path) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspaces" / "workspace"
    repo = tmp_path / "repos" / "goed2k-server"
    workspace.mkdir(parents=True)
    repo.mkdir(parents=True)
    (repo / "go.mod").write_text("module example\n", encoding="utf-8")
    (workspace / "deps.json").write_text(
        json.dumps({"workspace": {"repos": {"ed2k_server": "..\\..\\repos\\goed2k-server"}}}),
        encoding="utf-8",
    )

    assert module.resolve_manifest_repo(workspace, "ed2k_server") == repo.resolve()
    assert goed2k.resolve_ed2k_server_repo(workspace, None) == repo.resolve()


def test_resolve_ed2k_server_exe_defaults_to_output_root(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspaces" / "workspace"
    output_root = tmp_path.parent / f"{tmp_path.name}-output"
    monkeypatch.setenv("EMULEBB_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("EMULEBB_WORKSPACE_OUTPUT_ROOT", str(output_root))

    resolved = goed2k.resolve_ed2k_server_exe(workspace, None)

    assert resolved == (output_root / "tools" / "goed2k-server" / "goed2k-server.exe").resolve()


def test_build_or_skip_ed2k_server_binary_honors_explicit_exe_without_manifest(tmp_path: Path) -> None:
    workspace = tmp_path / "vm" / "workspace"
    server_exe = tmp_path / "harness" / "tools" / "goed2k-server.exe"
    server_exe.parent.mkdir(parents=True)
    server_exe.write_bytes(b"")

    result = goed2k.build_or_skip_ed2k_server_binary(
        workspace,
        server_exe,
        exe_override=str(server_exe),
    )

    assert result["return_code"] == 0
    assert result["server_exe"] == str(server_exe)
    assert result["skipped"] is True
    assert result["reason"] == "using explicit --ed2k-server-exe"


def test_env_ed2k_server_exe_override_uses_shared_harness_env() -> None:
    assert goed2k.env_ed2k_server_exe_override({}) is None
    assert goed2k.env_ed2k_server_exe_override({goed2k.ED2K_SERVER_EXE_ENV: "  "}) is None
    assert (
        goed2k.env_ed2k_server_exe_override(
            {goed2k.ED2K_SERVER_EXE_ENV: "C:/tools/goed2k-server.exe"}
        )
        == "C:/tools/goed2k-server.exe"
    )


def test_with_ed2k_server_exe_env_returns_child_env_copy(tmp_path: Path) -> None:
    base_env = {"KEEP": "1"}
    server_exe = tmp_path / "tools" / "goed2k-server.exe"

    child_env = goed2k.with_ed2k_server_exe_env(base_env, server_exe)

    assert child_env["KEEP"] == "1"
    assert child_env[goed2k.ED2K_SERVER_EXE_ENV] == str(server_exe.resolve())
    assert goed2k.ED2K_SERVER_EXE_ENV not in base_env


def test_stop_server_processes_uses_shared_goed2k_process_name_on_windows(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_run(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return None

    monkeypatch.setattr(goed2k.os, "name", "nt", raising=False)
    monkeypatch.setattr(goed2k.subprocess, "run", fake_run)

    goed2k.stop_server_processes()

    assert calls == [
        {
            "command": ["taskkill", "/IM", "goed2k-server.exe", "/T", "/F"],
            "stdout": goed2k.subprocess.DEVNULL,
            "stderr": goed2k.subprocess.DEVNULL,
            "check": False,
        }
    ]


def test_stop_server_processes_is_noop_off_windows(monkeypatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(goed2k.os, "name", "posix", raising=False)
    monkeypatch.setattr(goed2k.subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs)))

    goed2k.stop_server_processes()

    assert calls == []


def test_prepare_ed2k_server_binary_centralizes_resolution_and_build(monkeypatch, tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    server_exe = tmp_path / "tools" / "goed2k-server.exe"

    monkeypatch.setattr(goed2k, "resolve_ed2k_server_exe", lambda _workspace, override: Path(override).resolve())
    monkeypatch.setattr(
        goed2k,
        "build_or_skip_ed2k_server_binary",
        lambda workspace_root, resolved_exe, **kwargs: {
            "workspace_root": str(workspace_root),
            "server_exe": str(resolved_exe),
            "repo_override": kwargs["repo_override"],
            "exe_override": kwargs["exe_override"],
        },
    )

    prepared = goed2k.prepare_ed2k_server_binary(
        workspace,
        repo_override="repo-override",
        exe_override=str(server_exe),
    )

    assert prepared.server_exe == server_exe.resolve()
    assert prepared.build["workspace_root"] == str(workspace)
    assert prepared.build["server_exe"] == str(server_exe.resolve())
    assert prepared.build["repo_override"] == "repo-override"
    assert prepared.build["exe_override"] == str(server_exe)


def test_resolve_client2_app_exe_uses_emulebb_main_executable(tmp_path: Path) -> None:
    module = load_suite_module()
    workspace = tmp_path / "workspaces" / "workspace"
    client2_exe = workspace / "app" / "emulebb-main" / "srchybrid" / "x64" / "Release" / "emulebb.exe"
    client2_exe.parent.mkdir(parents=True)
    client2_exe.write_bytes(b"")

    assert module.resolve_client2_app_exe(workspace, "Release", None) == client2_exe.resolve()


def test_resolve_client2_app_exe_honors_override(tmp_path: Path) -> None:
    module = load_suite_module()
    override = tmp_path / "custom" / "harness.exe"
    override.parent.mkdir()
    override.write_bytes(b"")

    assert module.resolve_client2_app_exe(tmp_path / "workspace", "Release", str(override)) == override.resolve()


def test_choose_distinct_ports_probes_explicit_lan_bind_addr(monkeypatch) -> None:
    module = load_suite_module()
    availability_checks: list[tuple[int, str | None, bool]] = []

    def fake_is_port_available(port: int, *, host: str | None = None, udp: bool = False) -> bool:
        availability_checks.append((port, host, udp))
        return True

    monkeypatch.setattr(module, "is_port_available", fake_is_port_available)
    monkeypatch.setattr(module, "ED2K_LOCAL_PORT_MIN", 6200)
    monkeypatch.setattr(module, "ED2K_LOCAL_PORT_MAX", 6209)
    monkeypatch.setattr(module.random, "randrange", lambda _start, _stop: 6200)

    ports = module.choose_distinct_ports("172.24.112.1")

    assert ports["ed2k_tcp"] == 6200
    assert ports["ed2k_udp"] == 6204
    assert ports["ed2k_admin"] == 6201
    assert ports["client1_rest"] == 6202
    assert ports["client2_rest"] == 6203
    assert ports["client1_tcp"] == 6205
    assert ports["client1_udp"] == 6206
    assert ports["client2_tcp"] == 6207
    assert ports["client2_udp"] == 6208
    assert all(host == "172.24.112.1" for _port, host, _udp in availability_checks)
    assert availability_checks[:2] == [
        (6200, "172.24.112.1", False),
        (6204, "172.24.112.1", True),
    ]
    assert (6206, "172.24.112.1", True) in availability_checks
    assert (6208, "172.24.112.1", True) in availability_checks


def test_godzilla_choose_ports_probes_explicit_lan_bind_addr(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_port_bind_test")
    observed: dict[str, str | None] = {}
    availability_checks: list[tuple[int, str | None, bool]] = []
    next_port = iter(range(6300, 6310))

    def fake_choose_distinct_ports(host: str | None = None) -> dict[str, int]:
        observed["dtt_host"] = host
        return {"ed2k_tcp": 4662, "ed2k_udp": 4672, "client1_tcp": 4663, "client1_udp": 4673, "client1_rest": 4711}

    def fake_choose_listen_port(host: str | None = None) -> int:
        observed["extra_host"] = host
        return next(next_port)

    def fake_is_port_available(port: int, *, host: str | None = None, udp: bool = False) -> bool:
        availability_checks.append((port, host, udp))
        return True

    monkeypatch.setattr(godzilla.dtt, "choose_distinct_ports", fake_choose_distinct_ports)
    monkeypatch.setattr(godzilla.rest_smoke, "choose_listen_port", fake_choose_listen_port)
    monkeypatch.setattr(godzilla.dtt, "is_port_available", fake_is_port_available)

    ports = godzilla.choose_ports(extra_emulebb_clients=1, lan_bind_addr="172.24.112.3")

    assert ports["extra_emulebb_0_rest"] == 6302
    assert observed == {"dtt_host": "172.24.112.3", "extra_host": "172.24.112.3"}
    assert all(host == "172.24.112.3" for _port, host, _udp in availability_checks)


def test_discover_interface_ipv4_falls_back_to_hostname_when_windows_adapter_query_fails(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(
        module.windows_processes,
        "collect_adapter_ipv4_addresses",
        lambda _interface_name="": (_ for _ in ()).throw(RuntimeError("wmi unavailable")),
    )
    monkeypatch.setattr(module.socket, "gethostname", lambda: "host")
    monkeypatch.setattr(module.socket, "getfqdn", lambda: "host.local")
    monkeypatch.setattr(
        module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(module.socket.AF_INET, None, None, None, ("192.0.2.10", 0))],
    )

    assert module.discover_interface_ipv4("") == "192.0.2.10"


def test_discover_interface_ipv4_reports_named_interface_adapter_query_failure(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(
        module.windows_processes,
        "collect_adapter_ipv4_addresses",
        lambda _interface_name="": (_ for _ in ()).throw(RuntimeError("wmi unavailable")),
    )

    with pytest.raises(RuntimeError, match="Ethernet"):
        module.discover_interface_ipv4("Ethernet")


def test_resolve_lan_p2p_bind_address_defaults_to_lan_bind(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module, "discover_interface_ipv4", lambda _name: "192.0.2.99")

    assert module.resolve_lan_p2p_bind_address(lan_bind_addr="192.0.2.10") == "192.0.2.10"


def test_resolve_lan_p2p_bind_address_honors_explicit_interface(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module, "discover_interface_ipv4", lambda name: f"192.0.2.{len(name)}")

    assert module.resolve_lan_p2p_bind_address(
        lan_bind_addr="192.0.2.10",
        p2p_bind_interface_name="Ethernet",
    ) == "192.0.2.8"


def test_resolve_lan_p2p_bind_address_honors_explicit_address(monkeypatch) -> None:
    module = load_suite_module()
    monkeypatch.setattr(module, "discover_interface_ipv4", lambda _name: "192.0.2.99")

    assert module.resolve_lan_p2p_bind_address(
        lan_bind_addr="192.0.2.10",
        p2p_bind_interface_name="Ethernet",
        p2p_bind_interface_address="192.0.2.44",
    ) == "192.0.2.44"


def test_write_server_met_creates_single_server_with_numeric_and_dynamic_ip(tmp_path: Path) -> None:
    module = load_suite_module()
    server_met = tmp_path / "profile" / "config" / "server.met"

    module.write_server_met(server_met, address="10.44.55.66", port=4711, name="local-ed2k")

    data = server_met.read_bytes()
    assert data[:5] == struct.pack("<BI", module.SERVER_MET_HEADER, 1)
    assert data[5:9] == bytes([10, 44, 55, 66])
    port, tag_count = struct.unpack("<HI", data[9:15])
    assert port == 4711
    assert tag_count == 3
    assert b"local-ed2k" in data
    assert b"10.44.55.66" in data


def test_build_server_config_uses_workspace_artifact_paths(tmp_path: Path) -> None:
    config_path = tmp_path / "state" / "artifacts" / "server" / "config.json"
    catalog_path = tmp_path / "state" / "artifacts" / "server" / "catalog.json"

    config = goed2k.build_server_config(
        config_path,
        ed2k_port=4661,
        admin_port=8080,
        catalog_path=catalog_path,
        token="secret",
        admin_address="192.0.2.10",
        ed2k_address="192.0.2.10",
    )

    payload = json.loads(config_path.read_text(encoding="utf-8"))
    assert payload == config
    assert payload["listen_address"] == "192.0.2.10:4661"
    assert payload["admin_listen_address"] == "192.0.2.10:8080"
    assert payload["catalog_path"] == str(catalog_path)
    assert payload["protocol_obfuscation"] is True
    assert payload["tcp_flags"] == goed2k.SERVER_TCP_FLAG_TCPOBFUSCATION
    assert payload["aux_port"] == 0
    assert payload["server_udp"] is True


def test_build_server_config_allows_protocol_overrides(tmp_path: Path) -> None:
    config_path = tmp_path / "server" / "config.json"
    catalog_path = tmp_path / "server" / "catalog.json"

    config = goed2k.build_server_config(
        config_path,
        ed2k_port=4661,
        admin_port=8080,
        catalog_path=catalog_path,
        token="secret",
        admin_address="192.0.2.10",
        ed2k_address="192.0.2.10",
        protocol_obfuscation=False,
        server_udp=False,
    )

    assert config["protocol_obfuscation"] is False
    assert config["tcp_flags"] == 0
    assert config["server_udp"] is False


def test_build_server_config_allows_admin_bind_override(tmp_path: Path) -> None:
    config_path = tmp_path / "server" / "config.json"
    catalog_path = tmp_path / "server" / "catalog.json"

    config = goed2k.build_server_config(
        config_path,
        ed2k_port=4661,
        admin_port=8080,
        catalog_path=catalog_path,
        token="secret",
        admin_address="192.0.2.10",
        ed2k_address="192.0.2.10",
    )

    assert config["admin_listen_address"] == "192.0.2.10:8080"
    assert json.loads(config_path.read_text(encoding="utf-8"))["admin_listen_address"] == "192.0.2.10:8080"


def test_build_server_config_rejects_missing_ed2k_bind(tmp_path: Path) -> None:
    config_path = tmp_path / "server" / "config.json"
    catalog_path = tmp_path / "server" / "catalog.json"

    with pytest.raises(ValueError, match="explicit LAN bind address"):
        goed2k.build_server_config(
            config_path,
            ed2k_port=4661,
            admin_port=8080,
            catalog_path=catalog_path,
            token="secret",
            admin_address="192.0.2.10",
        )


def test_build_server_config_allows_ed2k_bind_override(tmp_path: Path) -> None:
    config_path = tmp_path / "server" / "config.json"
    catalog_path = tmp_path / "server" / "catalog.json"

    config = goed2k.build_server_config(
        config_path,
        ed2k_port=4661,
        admin_port=8080,
        catalog_path=catalog_path,
        token="secret",
        admin_address="192.0.2.10",
        ed2k_address="192.0.2.20",
    )

    assert config["listen_address"] == "192.0.2.20:4661"
    assert json.loads(config_path.read_text(encoding="utf-8"))["listen_address"] == "192.0.2.20:4661"


def test_launch_ed2k_server_centralizes_catalog_config_start_and_health(monkeypatch, tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    server_dir = tmp_path / "server"
    server_exe = tmp_path / "tools" / "goed2k-server.exe"
    fake_process = object()
    calls: dict[str, object] = {}

    monkeypatch.setattr(goed2k, "resolve_ed2k_server_exe", lambda _workspace, _override: server_exe)
    monkeypatch.setattr(
        goed2k,
        "build_or_skip_ed2k_server_binary",
        lambda _workspace, exe, **_kwargs: {"server_exe": str(exe), "return_code": 0},
    )

    def fake_start(exe: Path, config_path: Path, log_path: Path):
        calls["start"] = {"exe": exe, "config_path": config_path, "log_path": log_path}
        return fake_process

    monkeypatch.setattr(goed2k, "start_ed2k_server", fake_start)
    monkeypatch.setattr(goed2k, "wait_for_admin_health", lambda base_url, timeout: {"base_url": base_url, "timeout": timeout})

    launch = goed2k.launch_ed2k_server(
        workspace_root=workspace,
        server_dir=server_dir,
        ed2k_port=4661,
        admin_port=8080,
        token="secret",
        admin_address="192.0.2.10",
        ed2k_address="192.0.2.10",
        catalog_files=[
            goed2k.catalog_file(
                file_hash="00112233445566778899aabbccddeeff",
                name="fixture.bin",
                size=123,
                endpoints=[{"host": "192.0.2.20", "port": 4662}],
            )
        ],
        repo_override="repo-override",
        exe_override="exe-override",
        health_timeout_seconds=12.5,
    )

    assert launch.process is fake_process
    assert launch.admin_base_url == "http://192.0.2.10:8080"
    assert launch.build["server_exe"] == str(server_exe)
    assert launch.health == {"base_url": "http://192.0.2.10:8080", "timeout": 12.5}
    assert calls["start"] == {
        "exe": server_exe,
        "config_path": server_dir / "config.json",
        "log_path": server_dir / "server.log",
    }
    assert json.loads((server_dir / "catalog.json").read_text(encoding="utf-8"))["files"] == [
        {
            "hash": "00112233445566778899AABBCCDDEEFF",
            "name": "fixture.bin",
            "size": 123,
            "file_type": "Archive",
            "extension": "bin",
            "sources": 1,
            "complete_sources": 1,
            "endpoints": [{"host": "192.0.2.20", "port": 4662}],
        }
    ]
    assert launch.config["listen_address"] == "192.0.2.10:4661"
    assert launch.config["admin_listen_address"] == "192.0.2.10:8080"


def test_deterministic_transfer_reuses_shared_goed2k_launcher() -> None:
    module = load_suite_module()
    script_text = Path(module.__file__).read_text(encoding="utf-8")

    assert "goed2k.launch_ed2k_server(" in script_text
    assert "ed2k_address=p2p_address" in script_text
    assert "goed2k.start_ed2k_server(" not in script_text
    assert "goed2k.build_or_skip_ed2k_server_binary(" not in script_text


def test_wait_for_server_file_endpoint_reuses_shared_admin_polling(monkeypatch) -> None:
    monkeypatch.setattr(
        goed2k,
        "admin_request",
        lambda *_args, **_kwargs: {
            "data": [
                {
                    "hash": "00112233445566778899AABBCCDDEEFF",
                    "name": "fixture.bin",
                    "endpoints": [{"host": "192.0.2.10", "port": 4662}],
                }
            ]
        },
    )
    monkeypatch.setattr(goed2k.live_common, "wait_for", lambda resolve, *_args: resolve())

    row = goed2k.wait_for_server_file_endpoint(
        "http://192.0.2.10:8080",
        "secret",
        "00112233445566778899aabbccddeeff",
        "192.0.2.10",
        4662,
        1.0,
    )

    assert row["name"] == "fixture.bin"


def test_parse_exported_ed2k_file_link() -> None:
    module = load_suite_module()

    parsed = module.parse_ed2k_file_link(
        "ed2k://|file|fixture.bin|123|0123456789ABCDEF0123456789ABCDEF|/|sources,10.1.2.3:4662|/"
    )

    assert parsed == {
        "name": "fixture.bin",
        "size": 123,
        "hash": "0123456789abcdef0123456789abcdef",
    }


def test_wait_for_emule_shared_file_link_uses_explicit_pagination(monkeypatch) -> None:
    module = load_suite_module()
    calls: list[str] = []
    fixture_hash = "0123456789abcdef0123456789abcdef"

    def fake_http_request(_base_url, path, **_kwargs):
        calls.append(path)
        if path == "/api/v1/shared-files?offset=0&limit=100":
            return {"status": 200, "json": {"items": [{"name": "fixture.bin", "hash": fixture_hash.upper()}]}}
        return {"status": 200, "json": {"link": f"ed2k://|file|fixture.bin|123|{fixture_hash}|/"}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    def fake_wait_for(resolve, *_args):
        return resolve() or resolve()

    monkeypatch.setattr(module.live_common, "wait_for", fake_wait_for)

    result = module.wait_for_emule_shared_file_link(
        "http://127.0.0.1:4711",
        "secret",
        file_name="fixture.bin",
        timeout_seconds=1.0,
    )

    assert calls[0] == "/api/v1/shared-files?offset=0&limit=100"
    assert calls[1] == f"/api/v1/shared-files/{fixture_hash}/ed2k-link"
    assert result["hash"] == fixture_hash


def test_wait_for_emule_shared_file_link_accepts_link_variants(monkeypatch) -> None:
    module = load_suite_module()
    fixture_hash = "0123456789abcdef0123456789abcdef"

    def fake_http_request(_base_url, path, **_kwargs):
        if path == "/api/v1/shared-files?offset=0&limit=100":
            return {"status": 200, "json": [{"name": "fixture.bin", "hash": fixture_hash}]}
        return {"status": 200, "json": {"ed2kLinks": [f"ed2k://|file|fixture.bin|123|{fixture_hash}|/"]}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    def fake_wait_for(resolve, *_args):
        return resolve() or resolve()

    monkeypatch.setattr(module.live_common, "wait_for", fake_wait_for)

    result = module.wait_for_emule_shared_file_link(
        "http://127.0.0.1:4711",
        "secret",
        file_name="fixture.bin",
        timeout_seconds=1.0,
    )

    assert result["link"] == f"ed2k://|file|fixture.bin|123|{fixture_hash}|/"


def test_wait_for_emule_shared_file_link_falls_back_to_published_row(monkeypatch) -> None:
    module = load_suite_module()
    fixture_hash = "0123456789abcdef0123456789abcdef"

    def fake_http_request(_base_url, path, **_kwargs):
        if path == "/api/v1/shared-files?offset=0&limit=100":
            return {
                "status": 200,
                "raw_json": {
                    "data": {
                        "items": [
                            {
                                "name": "fixture.bin",
                                "hash": fixture_hash.upper(),
                                "publishedEd2k": True,
                                "sizeBytes": 123,
                            }
                        ]
                    },
                    "meta": {"apiVersion": "v1"},
                },
            }
        return {"status": 404, "body_text": "missing"}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    result = module.wait_for_emule_shared_file_link(
        "http://127.0.0.1:4711",
        "secret",
        file_name="fixture.bin",
        timeout_seconds=1.0,
    )

    assert result["link"] == f"ed2k://|file|fixture.bin|123|{fixture_hash}|/"
    assert result["observations"][-1]["link_source"] == "shared_file_row"


def test_wait_for_emule_shared_file_link_reports_list_failures(monkeypatch) -> None:
    module = load_suite_module()

    monkeypatch.setattr(
        module.rest_smoke,
        "http_request",
        lambda *_args, **_kwargs: {"status": 503, "body_text": "not ready"},
    )
    monkeypatch.setattr(
        module.rest_smoke,
        "require_json_array",
        lambda _result, _status: (_ for _ in ()).throw(AssertionError("not an array")),
    )
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    with pytest.raises(RuntimeError) as exc_info:
        module.wait_for_emule_shared_file_link(
            "http://127.0.0.1:4711",
            "secret",
            file_name="fixture.bin",
            timeout_seconds=1.0,
        )

    message = str(exc_info.value)
    assert "Timed out waiting for eMuleBB shared link" in message
    assert "'status': 503" in message


def test_write_fixture_file_is_deterministic(tmp_path: Path) -> None:
    module = load_suite_module()
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    first_hash = module.write_fixture_file(first, 4097)
    second_hash = module.write_fixture_file(second, 4097)

    assert first.read_bytes() == second.read_bytes()
    assert first_hash == second_hash == module.file_sha256(first)


def test_write_fixture_file_seed_changes_bytes(tmp_path: Path) -> None:
    module = load_suite_module()
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"

    first_hash = module.write_fixture_file(first, 4097)
    second_hash = module.write_fixture_file(second, 4097, seed=0xE1BB2026)

    assert first.read_bytes() != second.read_bytes()
    assert first_hash != second_hash
    assert second_hash == module.file_sha256(second)


def test_configure_client_profile_disables_private_server_filter(tmp_path: Path) -> None:
    module = load_suite_module()
    config_dir = tmp_path / "profile" / "config"
    config_dir.mkdir(parents=True)
    module.live_common.write_utf16_ini_text(
        config_dir / "preferences.ini",
        "[eMule]\nFilterBadIPs=1\nIPFilterEnabled=1\n[WebServer]\nEnabled=0\n",
    )

    module.configure_client_profile(
        config_dir=config_dir,
        app_exe=tmp_path / "app" / "emulebb.exe",
        nick=module.CLIENT01.nick,
        tcp_port=4662,
        udp_port=4672,
        ed2k_enabled=True,
        autoconnect=False,
    )

    text = module.live_common.read_ini_text(config_dir / "preferences.ini")
    emule_section = text.split("[WebServer]", 1)[0]
    assert "FilterBadIPs=0" in emule_section
    assert "IPFilterEnabled=0" in emule_section
    assert f"DownloadCapacity={module.DETERMINISTIC_BANDWIDTH_CAPACITY_KIB}" in emule_section
    assert f"UploadCapacity={module.DETERMINISTIC_BANDWIDTH_CAPACITY_KIB}" in emule_section
    assert f"UploadCapacityNew={module.DETERMINISTIC_BANDWIDTH_CAPACITY_KIB}" in emule_section
    assert f"MaxUpload={module.DETERMINISTIC_BANDWIDTH_LIMIT_KIB}" in emule_section
    assert f"MaxDownload={module.DETERMINISTIC_BANDWIDTH_LIMIT_KIB}" in emule_section
    assert "MaxUploadClientsAllowed=32" in text
    assert module.read_preferences_snapshot(config_dir)["CryptLayerSupported"] is None
    assert "SaveLogToDisk=1" in emule_section
    assert "SaveDebugToDisk=1" in emule_section
    assert "VerboseOptions=1" in emule_section
    assert "Verbose=1" in emule_section
    assert "FullVerbose=1" in emule_section
    assert "MaxLogFileSize=10485760" in emule_section
    assert "MaxLogBuff=256" in emule_section
    assert "CommitFiles=2" in emule_section
    assert "FileBufferSize=16384" in emule_section
    assert "FileBufferTimeLimit=1" in emule_section
    assert "AllocateFullFile=0" in emule_section
    assert "SparsePartFiles=0" in emule_section
    assert f"Nick={module.CLIENT01.nick}" in emule_section
    assert "EnableUPnP=0" in text


def test_configure_client_profile_can_apply_protocol_obfuscation_preferences(tmp_path: Path) -> None:
    module = load_suite_module()
    config_dir = tmp_path / "profile" / "config"
    config_dir.mkdir(parents=True)
    module.live_common.write_utf16_ini_text(config_dir / "preferences.ini", "[eMule]\n[WebServer]\n")

    module.configure_client_profile(
        config_dir=config_dir,
        app_exe=tmp_path / "app" / "emulebb.exe",
        nick=module.CLIENT01.nick,
        tcp_port=4662,
        udp_port=4672,
        ed2k_enabled=True,
        autoconnect=True,
        p2p_bind_addr="192.0.2.10",
        crypt_layer_supported=True,
        crypt_layer_requested=True,
        crypt_layer_required=True,
        crypt_tcp_padding_length=128,
    )

    text = module.live_common.read_ini_text(config_dir / "preferences.ini")
    emule_section = text.split("[WebServer]", 1)[0]
    assert "BindAddr=192.0.2.10" in emule_section
    assert "CryptLayerSupported=1" in emule_section
    assert "CryptLayerRequested=1" in emule_section
    assert "CryptLayerRequired=1" in emule_section
    assert "CryptTCPPaddingLength=128" in emule_section


def test_configure_client_profile_prefers_p2p_interface_over_bind_address(tmp_path: Path) -> None:
    module = load_suite_module()
    config_dir = tmp_path / "profile" / "config"
    config_dir.mkdir(parents=True)
    module.live_common.write_utf16_ini_text(config_dir / "preferences.ini", "[eMule]\n[WebServer]\n")

    module.configure_client_profile(
        config_dir=config_dir,
        app_exe=tmp_path / "app" / "emulebb.exe",
        nick=module.CLIENT01.nick,
        tcp_port=4662,
        udp_port=4672,
        ed2k_enabled=True,
        autoconnect=True,
        p2p_bind_interface_name="hide.me",
        p2p_bind_addr="10.54.210.222",
    )

    text = module.live_common.read_ini_text(config_dir / "preferences.ini")
    emule_section = text.split("[WebServer]", 1)[0]
    assert "BindInterface=hide.me" in emule_section
    assert re.search(r"BindAddr=\r?\n", emule_section)
    assert "BindAddr=10.54.210.222" not in emule_section
    assert "BlockNetworkWhenBindUnavailableAtStartup=1" in emule_section


def test_configure_client_profile_preserves_recursive_shared_directory_contract(tmp_path: Path) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_recursive_share_test")
    root = tmp_path / "library"
    (root / "000").mkdir(parents=True)
    (root / "001").mkdir()
    (root / "000" / "a.bin").write_bytes(b"a")
    (root / "001" / "b.bin").write_bytes(b"b")

    shared_dirs = godzilla.generated_library_shared_dirs(root)

    assert shared_dirs == [
        godzilla.live_common.win_path(root, trailing_slash=True),
        godzilla.live_common.win_path(root / "000", trailing_slash=True),
        godzilla.live_common.win_path(root / "001", trailing_slash=True),
    ]


def test_godzilla_runtime_root_is_drive_letter_only() -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_runtime_root_test")

    assert godzilla.parse_args(["--lan-bind-addr", "192.0.2.10"]).vhd_runtime_root == "drive-letter"
    with pytest.raises(SystemExit):
        godzilla.parse_args(["--lan-bind-addr", "192.0.2.10", "--vhd-runtime-root", "folder-mount"])


def test_godzilla_stage_defaults_to_full_and_accepts_launch_scale() -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_stage_test")

    assert godzilla.parse_args(["--lan-bind-addr", "192.0.2.10"]).stage == "full"
    assert godzilla.parse_args(["--lan-bind-addr", "192.0.2.10", "--stage", "launch-scale"]).stage == "launch-scale"
    with pytest.raises(SystemExit):
        godzilla.parse_args(["--lan-bind-addr", "192.0.2.10", "--stage", "unknown"])


def test_godzilla_lan_mode_uses_x_local_ip(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_lan_env_test")
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    args = godzilla.parse_args(["--lan-bind-addr", "192.0.2.10"])
    godzilla.validate_args(args)

    assert args.total_client_count == 30
    assert args.extra_emulebb_clients == 27
    assert godzilla.resolve_local_p2p_address(args) == "192.0.2.10"
    assert godzilla.resolve_lan_bind_addr(args, "192.0.2.10") == "192.0.2.10"


def test_godzilla_generate_library_reports_failed_path(monkeypatch, tmp_path: Path) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_generate_library_error_test")
    args = godzilla.parse_args(
        [
            "--total-client-count",
            "3",
            "--lan-bind-addr",
            "192.0.2.10",
            "--emulebb-files",
            "1",
            "--harness-files",
            "1",
            "--vhd-size-mb",
            "4103",
        ]
    )
    godzilla.validate_args(args)

    def fail_write(_path: Path, *, size_bytes: int, seed: int) -> str:
        raise PermissionError("denied")

    monkeypatch.setattr(godzilla, "write_generated_file", fail_write)

    with pytest.raises(RuntimeError) as exc_info:
        godzilla.generate_library(tmp_path / "library", owner_key="emulebb", count=1, args=args)

    message = str(exc_info.value)
    assert "owner='emulebb'" in message
    assert "index=0" in message
    assert "emulebb-godzilla-00000" in message


def test_godzilla_spiral_hammer_runs_rest_actions_without_optional_clients(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_rest_spiral_test")

    monkeypatch.setattr(godzilla, "server_telemetry_snapshot", lambda *_args: {"stats": {"clients": 2}})
    monkeypatch.setattr(godzilla.time, "sleep", lambda *_args: None)
    monkeypatch.setattr(godzilla.rest_smoke, "http_request", lambda *_args, **_kwargs: {"status": 200, "json": []})
    monkeypatch.setattr(godzilla.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})

    report = godzilla.run_spiral_hammer(
        base_url="http://127.0.0.1:1",
        api_key="secret",
        admin_base_url="http://127.0.0.1:2",
        links=["ed2k://|file|a.bin|1|0123456789ABCDEF0123456789ABCDEF|/"],
        queries=["emulebb-godzilla-"],
        waves=1,
        sleep_seconds=0.0,
    )

    assert {action["kind"] for action in report["waves"][0]["actions"]} == {"rest-search", "rest-add", "rest-churn"}


def test_godzilla_mixed_client_evidence_reports_mfc_peer_swarm() -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_mfc_peer_evidence_test")

    evidence = godzilla.classify_godzilla_mixed_client_evidence(queued_transfer_counts={"harness": 7})

    assert evidence["classification"] == "emulebb-mfc-peer-swarm"
    assert evidence["evidence_strength"] == "full"
    assert evidence["optional_clients"] == []
    assert evidence["mfc_peer"]["queued_transfer_count"] == 7


def test_godzilla_transfer_row_hashes_use_live_rest_identifiers() -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_transfer_row_hash_test")

    rows = [
        {"hash": "aaa"},
        {"fileHash": "bbb"},
        {"id": 123},
        {"name": "missing-hash"},
    ]

    assert godzilla.transfer_row_hashes(rows) == ["aaa", "bbb", "123"]


def test_godzilla_app_process_id_uses_live_common_resolver(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_app_process_id_test")

    class AppWithBrokenProcessMethod:
        def process(self):
            raise TypeError("'int' object is not callable")

    monkeypatch.setattr(godzilla.live_common, "resolve_app_process_id", lambda _app: 4242)

    assert godzilla.app_process_id(AppWithBrokenProcessMethod()) == 4242


def test_godzilla_queue_downloads_uses_retry_rest_request(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_retry_queue_test")
    calls: list[tuple[str, str]] = []

    def fake_retry(_base_url, path, *, method="GET", **_kwargs):
        calls.append((method, path))
        return {"status": 200, "json": {"queued": True}, "transient_errors": [{"type": "ConnectionResetError"}]}

    monkeypatch.setattr(godzilla.dtt, "retry_rest_request", fake_retry)
    monkeypatch.setattr(godzilla.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})

    rows = godzilla.queue_emulebb_downloads("http://127.0.0.1:4711", "key", ["ed2k://|file|a|1|0|/"])

    assert rows == [{"status": 200}]
    assert calls == [("POST", "/api/v1/transfers")]


def test_godzilla_spiral_hammer_searches_use_retry_rest_request(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_retry_spiral_test")
    calls: list[tuple[str, str, dict[str, object]]] = []

    def fake_retry(_base_url, path, *, method="GET", json_body=None, **_kwargs):
        calls.append((method, path, dict(json_body or {})))
        return {"status": 200, "json": {"id": "search-1"}, "transient_errors": [{"type": "ConnectionAbortedError"}]}

    monkeypatch.setattr(godzilla.dtt, "retry_rest_request", fake_retry)
    monkeypatch.setattr(godzilla, "server_telemetry_snapshot", lambda *_args, **_kwargs: {"ok": True})
    monkeypatch.setattr(godzilla.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})

    result = godzilla.run_spiral_hammer(
        base_url="http://127.0.0.1:4711",
        api_key="key",
        admin_base_url="http://127.0.0.1:8080",
        links=[],
        queries=["alpha", "beta", "gamma"],
        waves=1,
        sleep_seconds=0.0,
    )

    assert result["waves"][0]["actions"][:3] == [
        {"kind": "rest-search", "query": "beta", "response": {"status": 200}},
        {"kind": "rest-search", "query": "gamma", "response": {"status": 200}},
        {"kind": "rest-search", "query": "alpha", "response": {"status": 200}},
    ]
    assert calls == [
        ("POST", "/api/v1/searches", {"query": "beta", "method": "server", "type": ""}),
        ("POST", "/api/v1/searches", {"query": "gamma", "method": "server", "type": ""}),
        ("POST", "/api/v1/searches", {"query": "alpha", "method": "server", "type": ""}),
    ]


def test_godzilla_control_plane_search_hammer_uses_retry_rest_request(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_retry_control_search_test")
    calls: list[tuple[str, str, dict[str, object]]] = []

    def fake_retry(_base_url, path, *, method="GET", json_body=None, **_kwargs):
        calls.append((method, path, dict(json_body or {})))
        return {"status": 200, "json": {"id": "search-1"}, "transient_errors": [{"type": "ConnectionAbortedError"}]}

    monkeypatch.setattr(godzilla.dtt, "retry_rest_request", fake_retry)
    monkeypatch.setattr(godzilla.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    monkeypatch.setattr(godzilla.rest_smoke, "wait_for_search_observation", lambda *_args, **_kwargs: {"observed": True})
    monkeypatch.setattr(godzilla.rest_smoke, "delete_all_searches", lambda *_args, **_kwargs: {"status": 200})

    result = godzilla.run_emulebb_search_hammer(
        "http://127.0.0.1:4711",
        "key",
        queries=["alpha", "beta"],
        rounds=2,
    )

    assert [row["start"] for row in result["rounds"]] == [{"status": 200}, {"status": 200}]
    assert [row["observation"] for row in result["rounds"]] == [{"observed": True}, {"observed": True}]
    assert result["cleanup"] == {"status": 200}
    assert calls == [
        ("POST", "/api/v1/searches", {"query": "alpha", "method": "server", "type": ""}),
        ("POST", "/api/v1/searches", {"query": "beta", "method": "server", "type": ""}),
    ]


def test_godzilla_log_marker_scan_counts_and_samples(tmp_path: Path) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_log_marker_scan_test")
    log_path = tmp_path / "emulebb-verbose.log"
    log_path.write_text(
        "\n".join(
            [
                "normal line",
                "Banned: Aggressive behaviour",
                "Clients: peer, Ban reason: Userhash changed (Found in TrackedClientsList)",
                "Removing client from upload list: Remote client cancelled transfer. In buffer: 16777216.00 TB",
            ]
        ),
        encoding="utf-8",
    )

    report = godzilla.scan_log_markers(
        {"primary": log_path},
        ["Banned:", "Ban reason:", "Userhash changed", "Remote client cancelled transfer", "In buffer: 16777216.00 TB"],
    )

    assert report["primary"]["counts"] == {
        "Banned:": 1,
        "Ban reason:": 1,
        "Userhash changed": 1,
        "Remote client cancelled transfer": 1,
        "In buffer: 16777216.00 TB": 1,
    }
    assert len(report["primary"]["samples"]) == 5


def test_godzilla_rejects_loopback_lan_bind(monkeypatch) -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_lan_loopback_test")
    args = godzilla.parse_args(
        [
            "--total-client-count",
            "3",
            "--lan-bind-addr",
            "127.0.0.1",
            "--emulebb-files",
            "1",
            "--harness-files",
            "1",
            "--vhd-size-mb",
            "4103",
        ]
    )
    godzilla.validate_args(args)

    with pytest.raises(RuntimeError):
        godzilla.resolve_local_p2p_address(args)


def test_godzilla_local_swarm_reuses_shared_goed2k_launcher() -> None:
    godzilla = load_script_module("godzilla-local-swarm.py", "godzilla_for_goed2k_launcher_test")
    script_text = Path(godzilla.__file__).read_text(encoding="utf-8")

    assert "goed2k.launch_ed2k_server(" in script_text
    assert "goed2k.start_ed2k_server(" not in script_text
    assert "goed2k.build_server_config(" not in script_text


def test_default_fixture_size_is_132_mib() -> None:
    module = load_suite_module()
    args = module.parse_args(["--lan-bind-addr", "192.0.2.10"])

    assert module.DEFAULT_FIXTURE_SIZE_BYTES == 132 * 1024 * 1024
    assert args.fixture_size_bytes == module.DEFAULT_FIXTURE_SIZE_BYTES
    assert args.transfer_completion_timeout_seconds == 900.0


def test_add_and_connect_server_reuses_preloaded_server(monkeypatch) -> None:
    module = load_suite_module()
    calls: list[tuple[str, str]] = []

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        calls.append((method, path))
        if path == "/api/v1/servers":
            return {"status": 200, "json": {"items": [{"address": "10.1.2.3", "port": 4661, "name": "local"}]}}
        if path == "/api/v1/status":
            return {
                "status": 200,
                "json": {
                    "connected": True,
                    "currentServer": {"address": "10.1.2.3", "port": 4661, "name": "local"},
                },
            }
        return {"status": 200, "json": {"connected": True}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_object", lambda result, _status: dict(result["json"]))
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    monkeypatch.setattr(module.live_common, "wait_for", lambda resolve, *_args: resolve())

    result = module.add_and_connect_server(
        "http://127.0.0.1:4711",
        "key",
        address="10.1.2.3",
        port=4661,
        timeout_seconds=1.0,
    )

    assert result["add"]["preloaded"] is True
    assert ("POST", "/api/v1/servers") not in calls
    assert ("POST", "/api/v1/servers/10.1.2.3:4661/operations/connect") in calls


def test_add_and_connect_server_retries_transient_rest_socket_abort(monkeypatch) -> None:
    module = load_suite_module()
    calls: list[tuple[str, str]] = []
    first_call = True

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        nonlocal first_call
        calls.append((method, path))
        if first_call:
            first_call = False
            raise ConnectionAbortedError(10053, "socket aborted")
        if path == "/api/v1/servers":
            return {"status": 200, "json": [{"address": "10.1.2.3", "port": 4661, "name": "local"}]}
        if path == "/api/v1/status":
            return {
                "status": 200,
                "json": {
                    "connected": True,
                    "currentServer": {"address": "10.1.2.3", "port": 4661, "name": "local"},
                },
            }
        return {"status": 200, "json": {"connected": True}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "require_json_object", lambda result, _status: dict(result["json"]))
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"]})
    def fake_wait_for(resolve, *_args):
        return resolve() or resolve()

    monkeypatch.setattr(module.live_common, "wait_for", fake_wait_for)

    result = module.add_and_connect_server(
        "http://127.0.0.1:4711",
        "key",
        address="10.1.2.3",
        port=4661,
        timeout_seconds=2.0,
    )

    assert result["add"]["preloaded"] is True
    assert calls.count(("GET", "/api/v1/servers")) == 2
    assert ("POST", "/api/v1/servers/10.1.2.3:4661/operations/connect") in calls


def test_add_and_connect_server_waits_past_transitional_connect_response(monkeypatch) -> None:
    module = load_suite_module()
    calls: list[tuple[str, str]] = []
    status_payloads = [
        {
            "connected": False,
            "connecting": True,
            "currentServer": None,
            "serverCount": 1,
        },
        {
            "connected": True,
            "connecting": False,
            "currentServer": {"address": "10.1.2.3", "port": 4661, "name": "local"},
            "serverCount": 1,
        },
    ]

    def fake_http_request(_base_url, path, *, method="GET", **_kwargs):
        calls.append((method, path))
        if path == "/api/v1/servers":
            return {"status": 200, "json": [{"address": "10.1.2.3", "port": 4661, "name": "local"}]}
        if path == "/api/v1/servers/10.1.2.3:4661/operations/connect":
            payload = {
                "connected": False,
                "connecting": True,
                "currentServer": None,
                "serverCount": 1,
            }
            return {
                "status": 200,
                "content_type": "application/json; charset=utf-8",
                "json": payload,
                "raw_json": {"data": payload, "meta": {"apiVersion": "v1"}},
            }
        if path == "/api/v1/status":
            payload = status_payloads.pop(0)
            return {
                "status": 200,
                "content_type": "application/json; charset=utf-8",
                "json": payload,
                "raw_json": {"data": payload, "meta": {"apiVersion": "v1"}},
            }
        raise AssertionError(path)

    def fake_wait_for(resolve, *_args):
        return resolve() or resolve()

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"], "json": result["json"]})
    monkeypatch.setattr(module.live_common, "wait_for", fake_wait_for)

    result = module.add_and_connect_server(
        "http://127.0.0.1:4711",
        "key",
        address="10.1.2.3",
        port=4661,
        timeout_seconds=2.0,
    )

    assert result["connect"]["json"]["connecting"] is True
    assert result["connected"]["observations"][-1]["connected"] is True
    assert calls.count(("GET", "/api/v1/status")) == 2


def test_add_transfer_accepts_bulk_items_response_without_contract_gate(monkeypatch) -> None:
    module = load_suite_module()
    expected_hash = "9eced47df2edfbd72f29f93447d60b7b"
    item = {"hash": expected_hash.upper(), "name": "deterministic-two-client-transfer.bin", "ok": True}
    response = {
        "status": 200,
        "content_type": "application/json; charset=utf-8",
        "json": {"items": [item]},
        "raw_json": {"data": {"items": [item]}, "meta": {"apiVersion": "v1"}},
    }
    calls: list[tuple[str, str, dict[str, object]]] = []

    def fake_http_request(_base_url, path, *, method="GET", json_body=None, **_kwargs):
        calls.append((method, path, dict(json_body or {})))
        return response

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)
    monkeypatch.setattr(module.rest_smoke, "compact_http_result", lambda result: {"status": result["status"], "json": result["json"]})

    result = module.add_transfer("http://127.0.0.1:4711", "key", "ed2k://|file|a|1|9ECED47DF2EDFBD72F29F93447D60B7B|/", expected_hash)

    assert result["item"] == item
    assert calls == [
        (
            "POST",
            "/api/v1/transfers",
            {"link": "ed2k://|file|a|1|9ECED47DF2EDFBD72F29F93447D60B7B|/", "paused": False, "categoryId": 0},
        )
    ]


def test_wait_for_completed_file_timeout_carries_diagnostic_observations(tmp_path: Path) -> None:
    module = load_suite_module()
    snapshots = [{"transfer": {"status": 200, "json": {"state": "downloading"}}}]

    try:
        module.wait_for_completed_file(
            tmp_path / "incoming" / "fixture.bin",
            expected_size=10,
            expected_sha256="0" * 64,
            timeout_seconds=0.0,
            snapshot_callback=lambda: snapshots[0],
        )
    except module.TransferCompletionTimeout as exc:
        assert exc.observations[-1]["snapshot"] == snapshots[0]
    else:
        raise AssertionError("Expected TransferCompletionTimeout")


def test_collect_client1_transfer_snapshot_records_rest_and_workspace_files(monkeypatch, tmp_path: Path) -> None:
    module = load_suite_module()
    incoming_dir = tmp_path / "incoming"
    temp_dir = tmp_path / "temp"
    incoming_dir.mkdir()
    temp_dir.mkdir()
    part_file = temp_dir / "001.part"
    part_file.write_bytes(b"abc")
    requested_paths: list[str] = []

    def fake_http_request(_base_url, path, **_kwargs):
        requested_paths.append(path)
        return {"status": 200, "content_type": "application/json", "json": {"path": path}}

    monkeypatch.setattr(module.rest_smoke, "http_request", fake_http_request)

    snapshot = module.collect_client1_transfer_snapshot(
        base_url="http://127.0.0.1:4711",
        api_key="key",
        transfer_hash="a" * 32,
        incoming_path=incoming_dir / "fixture.bin",
        temp_dir=temp_dir,
        hash_limit_bytes=10,
    )

    assert requested_paths == [
        "/api/v1/transfers/" + "a" * 32,
        "/api/v1/transfers/" + "a" * 32 + "/details",
        "/api/v1/transfers/" + "a" * 32 + "/sources",
    ]
    assert snapshot["incoming_file"]["exists"] is False
    assert snapshot["temp_dir"][0]["sha256"] == module.file_sha256(part_file)
