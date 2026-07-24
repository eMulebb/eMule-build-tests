from __future__ import annotations

import json
import os
import sqlite3
import struct
from pathlib import Path

import pytest

from emule_test_harness import mfc_known_met, mfc_profile_import, rust_metadata


def _rust_repo() -> Path:
    return Path(__file__).resolve().parents[2].parent / "emulebb-rust"


def _tag_string(name_id: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return bytes([mfc_known_met.TAGTYPE_STRING]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<H", len(raw)) + raw


def _tag_uint64(name_id: int, value: int) -> bytes:
    return bytes([mfc_known_met.TAGTYPE_UINT64]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<Q", value)


def _tag_uint32(name_id: int, value: int) -> bytes:
    return bytes([mfc_known_met.TAGTYPE_UINT32]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<I", value)


def _known_record(
    *,
    modified_s: int,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
) -> bytes:
    tags = [
        _tag_string(mfc_known_met.FT_FILENAME, name),
        _tag_uint64(mfc_known_met.FT_FILESIZE, size_bytes),
        _tag_uint32(mfc_known_met.FT_ATTRANSFERRED, 1234),
        _tag_uint32(mfc_known_met.FT_ATREQUESTED, 9),
        _tag_uint32(mfc_known_met.FT_ATACCEPTED, 4),
    ]
    return (
        struct.pack("<I", modified_s)
        + bytes.fromhex(ed2k_hash)
        + struct.pack("<H", 0)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )


def _write_known_met(path: Path, records: list[bytes]) -> None:
    path.write_bytes(
        bytes([mfc_known_met.MET_HEADER_I64TAGS])
        + struct.pack("<I", len(records))
        + b"".join(records)
    )


def _server_name_tag(name: str) -> bytes:
    raw = name.encode("ascii")
    return bytes([0x80 | (mfc_known_met.TAGTYPE_STR1 + len(raw) - 1), 0x01]) + raw


def _write_server_met(path: Path) -> None:
    name = _server_name_tag("Local")
    path.write_bytes(
        bytes([mfc_profile_import.SERVER_MET_HEADER])
        + struct.pack("<I", 1)
        + bytes([45, 82, 80, 155])
        + struct.pack("<H", 5687)
        + struct.pack("<I", 1)
        + name
    )


def _write_nodes_dat(path: Path) -> None:
    data = bytearray()
    data.extend(struct.pack("<III", 0, 2, 1))
    data.extend(bytes.fromhex("11" * 16))
    data.extend(struct.pack("<I", int.from_bytes(bytes([1, 2, 3, 4]), "big")))
    data.extend(struct.pack("<HHB", 4672, 4662, 9))
    data.extend(bytes([2]))
    data.extend(struct.pack("<II", 0, 0x11223344))
    path.write_bytes(bytes(data))


def test_import_stock_mfc_profile_creates_fresh_rust_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")
    config = tmp_path / "stock-config"
    shared = tmp_path / "shared"
    rust_profile = tmp_path / "rust-profile"
    config.mkdir()
    shared.mkdir()
    payload = shared / "Shared.bin"
    payload.write_bytes(b"payload")
    modified_s = 1_700_000_000
    os.utime(payload, (modified_s, modified_s))
    (config / "shareddir.dat").write_text(str(shared) + "\r\n", encoding="utf-16")
    _write_known_met(
        config / "known.met",
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name=payload.name,
                size_bytes=payload.stat().st_size,
            )
        ],
    )
    (config / "known2_64.met").write_bytes(bytes([mfc_known_met.KNOWN2_MET_VERSION]))
    _write_server_met(config / "server.met")
    _write_nodes_dat(config / "nodes.dat")
    user_hash = bytes.fromhex("aaaaaaaaaabbccddeeff001122334455")
    (config / "preferences.dat").write_bytes(bytes([mfc_profile_import.PREFERENCES_DAT_VERSION]) + user_hash)

    summary = mfc_profile_import.import_stock_mfc_profile(
        rust_repo=_rust_repo(),
        emule_config_dir=config,
        rust_profile_dir=rust_profile,
        import_user_hash=True,
    )

    assert summary["sharedRoots"] == 1
    assert summary["accessibleSharedRoots"] == 1
    assert summary["servers"] == 1
    assert summary["kadBootstrapEndpoints"] == 1
    assert summary["importedUserHash"] is True
    assert summary["hashes"]["importedKnownRecords"] == 1
    assert summary["restBaseUrl"] == "http://192.0.2.10:58381/api/v1"
    assert summary["p2pBindIp"] is None
    assert summary["p2pBindInterface"] == "hide.me"
    db_path = rust_profile / rust_metadata.RUST_PROFILE_METADATA_FILE
    settings_path = rust_profile / "emulebb-rust-settings.toml"
    assert settings_path.is_file()
    settings_text = settings_path.read_text(encoding="utf-8")
    assert 'bindAddr = "192.0.2.10:58381"' in settings_text
    assert "127." not in settings_text
    with sqlite3.connect(db_path) as conn:
        roots = conn.execute("SELECT count(*) FROM shared_directory_roots WHERE enabled = 1").fetchone()[0]
        servers = conn.execute("SELECT address, port, name FROM servers").fetchall()
        kad = conn.execute("SELECT endpoint FROM kad_bootstrap_endpoints").fetchall()
        daemon_settings = {
            key: json.loads(value_json)
            for key, value_json in conn.execute("SELECT key, value_json FROM settings WHERE section = 'daemon'")
        }
        identity = conn.execute(
            "SELECT lower(hex(public_identity)) FROM local_identities WHERE identity_kind = 'ed2k-user-hash'"
        ).fetchone()[0]
        imported = conn.execute(
            """
            SELECT lower(hex(ed2k_hash)), display_name, size_bytes, modified_s,
                   all_time_uploaded_bytes, all_time_upload_requests, all_time_upload_accepts
            FROM imported_known_files
            """
        ).fetchall()
        manifests = conn.execute("SELECT count(*) FROM transfers").fetchone()[0]
    assert roots == 1
    assert servers == [("45.82.80.155", 5687, "Local")]
    assert kad == [("1.2.3.4:4672",)]
    assert daemon_settings.get("p2pBindInterface") == "hide.me"
    assert "p2pBindIp" not in daemon_settings
    assert identity == "aaaaaaaaaa0eccddeeff001122336f55"
    assert imported == [
        (
            "00112233445566778899aabbccddeeff",
            payload.name,
            payload.stat().st_size,
            modified_s,
            1234,
            9,
            4,
        )
    ]
    assert manifests == 0


def test_import_stock_mfc_profile_requires_rest_lan_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("X_LOCAL_IP", raising=False)
    config = tmp_path / "stock-config"
    rust_profile = tmp_path / "rust-profile"
    config.mkdir()
    (config / "shareddir.dat").write_text("C:\\shared\r\n", encoding="utf-16")
    _write_known_met(config / "known.met", [])

    with pytest.raises(RuntimeError, match="X_LOCAL_IP"):
        mfc_profile_import.import_stock_mfc_profile(
            rust_repo=_rust_repo(),
            emule_config_dir=config,
            rust_profile_dir=rust_profile,
        )


def test_import_stock_mfc_profile_rejects_existing_non_empty_target(tmp_path: Path) -> None:
    config = tmp_path / "stock-config"
    target = tmp_path / "rust-profile"
    config.mkdir()
    target.mkdir()
    (target / "existing.txt").write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="new or empty"):
        mfc_profile_import.import_stock_mfc_profile(
            rust_repo=_rust_repo(),
            emule_config_dir=config,
            rust_profile_dir=target,
        )


def test_parse_server_met_rejects_trailing_bytes(tmp_path: Path) -> None:
    server_met = tmp_path / "server.met"
    _write_server_met(server_met)
    server_met.write_bytes(server_met.read_bytes() + b"x")

    with pytest.raises(ValueError, match="trailing bytes"):
        mfc_profile_import.parse_server_met(server_met)


def test_load_recursive_roots_ignores_non_stock_monitored_sidecars(tmp_path: Path) -> None:
    config = tmp_path / "stock-config"
    config.mkdir()
    (config / "shareddir.dat").write_text("C:\\many\\one\r\nC:\\many\\two\r\n", encoding="utf-16")
    (config / "shareddir.monitored.dat").write_text("F:\\SharedRoot\r\n", encoding="utf-16")

    roots = mfc_profile_import._load_recursive_root_entries(config / "shareddir.dat")

    assert roots == [
        {"path": "C:\\many\\one\\", "recursive": True},
        {"path": "C:\\many\\two\\", "recursive": True},
    ]


def test_load_recursive_roots_collapses_fully_listed_directory_tree(tmp_path: Path) -> None:
    config = tmp_path / "stock-config"
    root = tmp_path / "MORE_SHR" / "mp3-albums"
    one = root / "artist-one"
    two = root / "artist-two"
    (one / "disc").mkdir(parents=True)
    two.mkdir(parents=True)
    config.mkdir()
    (config / "shareddir.dat").write_text(
        "\r\n".join(str(path) for path in [one, one / "disc", two]) + "\r\n",
        encoding="utf-16",
    )

    roots = mfc_profile_import._load_recursive_root_entries(config / "shareddir.dat")

    assert roots == [{"path": str(root) + "\\", "recursive": True}]


def test_load_recursive_roots_keeps_exact_dirs_when_tree_cannot_be_proved(tmp_path: Path) -> None:
    config = tmp_path / "stock-config"
    root = tmp_path / "shared"
    one = root / "one"
    missing = root / "missing"
    one.mkdir(parents=True)
    config.mkdir()
    (config / "shareddir.dat").write_text(f"{one}\r\n{missing}\r\n", encoding="utf-16")

    roots = mfc_profile_import._load_recursive_root_entries(config / "shareddir.dat")

    assert roots == [
        {"path": str(one) + "\\", "recursive": True},
        {"path": str(missing) + "\\", "recursive": True},
    ]
