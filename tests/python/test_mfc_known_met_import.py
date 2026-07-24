from __future__ import annotations

import os
import base64
import sqlite3
import struct
from pathlib import Path

from emule_test_harness import mfc_known_met, rust_metadata


def _rust_repo() -> Path:
    return Path(__file__).resolve().parents[2].parent / "emulebb-rust"


def _tag_string(name_id: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return bytes([mfc_known_met.TAGTYPE_STRING]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<H", len(raw)) + raw


def _tag_uint64(name_id: int, value: int) -> bytes:
    return bytes([mfc_known_met.TAGTYPE_UINT64]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<Q", value)


def _tag_uint32(name_id: int, value: int) -> bytes:
    return bytes([mfc_known_met.TAGTYPE_UINT32]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<I", value)


def _tag_named_uint64(name: str, value: int) -> bytes:
    raw = name.encode("ascii")
    return bytes([mfc_known_met.TAGTYPE_UINT64]) + struct.pack("<H", len(raw)) + raw + struct.pack("<Q", value)


def _tag_blob(name_id: int, value: bytes) -> bytes:
    return bytes([mfc_known_met.TAGTYPE_BLOB]) + struct.pack("<H", 1) + bytes([name_id]) + struct.pack("<I", len(value)) + value


def _known_record(
    *,
    modified_s: int,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    md4_hashset: list[str] | None = None,
    aich_blob: bytes | None = None,
    aich_root_base32: str | None = None,
    upload_priority: int | None = None,
    all_time_uploaded_bytes: int = 0,
    all_time_upload_requests: int = 0,
    all_time_upload_accepts: int = 0,
    last_request_s: int = 0,
) -> bytes:
    tags = [
        _tag_string(mfc_known_met.FT_FILENAME, name),
        _tag_uint64(mfc_known_met.FT_FILESIZE, size_bytes),
    ]
    if aich_blob is not None:
        tags.append(_tag_blob(mfc_known_met.FT_AICHHASHSET, aich_blob))
    if aich_root_base32 is not None:
        tags.append(_tag_string(mfc_known_met.FT_AICH_HASH, aich_root_base32))
    if upload_priority is not None:
        tags.append(_tag_uint32(mfc_known_met.FT_ULPRIORITY, upload_priority))
    if all_time_uploaded_bytes:
        tags.append(_tag_uint32(mfc_known_met.FT_ATTRANSFERRED, all_time_uploaded_bytes & 0xFFFF_FFFF))
        tags.append(_tag_uint32(mfc_known_met.FT_ATTRANSFERREDHI, all_time_uploaded_bytes >> 32))
    if all_time_upload_requests:
        tags.append(_tag_uint32(mfc_known_met.FT_ATREQUESTED, all_time_upload_requests))
    if all_time_upload_accepts:
        tags.append(_tag_uint32(mfc_known_met.FT_ATACCEPTED, all_time_upload_accepts))
    if last_request_s:
        tags.append(_tag_named_uint64(mfc_known_met.LAST_REQUEST_TAG_NAME, last_request_s))
    parts = md4_hashset or []
    return (
        struct.pack("<I", modified_s)
        + bytes.fromhex(ed2k_hash)
        + struct.pack("<H", len(parts))
        + b"".join(bytes.fromhex(part) for part in parts)
        + struct.pack("<I", len(tags))
        + b"".join(tags)
    )


def _write_known_met(path: Path, records: list[bytes]) -> None:
    path.write_bytes(
        bytes([mfc_known_met.MET_HEADER_I64TAGS])
        + struct.pack("<I", len(records))
        + b"".join(records)
    )


def test_parse_known_met_reads_identity_and_aich_blob(tmp_path: Path) -> None:
    aich_blob = bytes.fromhex("aa" * 20) + struct.pack("<H", 0)
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=1_700_000_000,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="Sample File.bin",
                size_bytes=1234,
                aich_blob=aich_blob,
            )
        ],
    )

    entries = mfc_known_met.parse_known_met(known_met)

    assert len(entries) == 1
    assert entries[0].ed2k_hash == "00112233445566778899aabbccddeeff"
    assert entries[0].name == "Sample File.bin"
    assert entries[0].size_bytes == 1234
    assert entries[0].aich_root == "aa" * 20


def test_parse_known_met_reads_stock_upload_stats_and_priority(tmp_path: Path) -> None:
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=1_700_000_000,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="Stats.bin",
                size_bytes=1234,
                upload_priority=mfc_known_met.PR_AUTO,
                all_time_uploaded_bytes=0x1_0000_0123,
                all_time_upload_requests=7,
                all_time_upload_accepts=3,
                last_request_s=1_700_000_111,
            )
        ],
    )

    entry = mfc_known_met.parse_known_met(known_met)[0]

    assert entry.upload_priority == "normal"
    assert entry.auto_upload_priority is True
    assert entry.all_time_uploaded_bytes == 0x1_0000_0123
    assert entry.all_time_upload_requests == 7
    assert entry.all_time_upload_accepts == 3
    assert entry.last_upload_request_ms == 1_700_000_111_000


def test_import_known_met_uses_known2_aich_hashset(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    payload = shared / "Large.bin"
    payload.write_bytes(b"x" * (rust_metadata.ED2K_PART_SIZE + 1))
    modified_s = 1_700_000_000
    os.utime(payload, (modified_s, modified_s))
    aich_root = bytes.fromhex("aa" * 20)
    aich_base32 = base64.b32encode(aich_root).decode("ascii").rstrip("=")
    known_met = tmp_path / "known.met"
    known2 = tmp_path / "known2_64.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name=payload.name,
                size_bytes=payload.stat().st_size,
                md4_hashset=["11" * 16, "22" * 16],
                aich_root_base32=aich_base32,
            )
        ],
    )
    known2.write_bytes(
        bytes([mfc_known_met.KNOWN2_MET_VERSION])
        + aich_root
        + struct.pack("<I", 2)
        + bytes.fromhex("bb" * 20)
        + bytes.fromhex("cc" * 20)
    )
    db_path = tmp_path / "metadata.sqlite"
    rust_metadata.create_metadata_db(_rust_repo(), db_path)

    summary = mfc_known_met.import_mfc_known_met_hashes(
        rust_repo=_rust_repo(),
        metadata_db=db_path,
        known_met=known_met,
        known2_64_met=known2,
        shared_roots=[shared],
    )

    assert summary["known2AichUsed"] == 1
    manifest = rust_metadata.read_transfer_manifest(db_path, "00112233445566778899aabbccddeeff")
    assert manifest is not None
    assert manifest["aich_root"] == "aa" * 20
    assert manifest["aich_hashset"] == ["bb" * 20, "cc" * 20]


def test_import_known_met_seeds_share_in_place_manifest(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    payload = shared / "Sample File.bin"
    payload.write_bytes(b"sample")
    modified_s = 1_700_000_000
    os.utime(payload, (modified_s, modified_s))
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name=payload.name,
                size_bytes=payload.stat().st_size,
            )
        ],
    )
    db_path = tmp_path / "metadata.sqlite"
    rust_metadata.create_metadata_db(_rust_repo(), db_path)

    summary = mfc_known_met.import_mfc_known_met_hashes(
        rust_repo=_rust_repo(),
        metadata_db=db_path,
        known_met=known_met,
        shared_roots=[shared],
    )

    assert summary["importedRecords"] == 1
    manifest = rust_metadata.read_transfer_manifest(db_path, "00112233445566778899aabbccddeeff")
    assert manifest is not None
    assert manifest["completed"] is True
    assert manifest["source_path"] == str(payload)
    assert manifest["source_mtime_ms"] // 1000 == modified_s
    assert manifest["md4_hashset_acquired"] is True
    with sqlite3.connect(db_path) as conn:
        source_row = conn.execute(
            """
            SELECT shared_file_sources.file_size, shared_file_sources.source_mtime_ms
            FROM shared_file_sources
            JOIN local_paths ON local_paths.id = shared_file_sources.path_id
            WHERE local_paths.display_path = ?
            """,
            (str(payload),),
        ).fetchone()
        piece_rows = conn.execute("SELECT count(*) FROM transfer_pieces").fetchone()[0]
        range_row = conn.execute(
            """
            SELECT start_offset, end_offset
            FROM verified_ranges
            """
        ).fetchone()
    assert source_row == (payload.stat().st_size, manifest["source_mtime_ms"])
    assert piece_rows == 0
    assert range_row == (0, payload.stat().st_size)


def test_seed_shared_directory_roots_persists_startup_roots(tmp_path: Path) -> None:
    db_path = tmp_path / "metadata.sqlite"
    rust_metadata.create_metadata_db(_rust_repo(), db_path)
    root = tmp_path / "share"

    rust_metadata.seed_shared_directory_roots(
        db_path,
        [
            {
                "path": str(root),
                "monitorOwned": False,
                "shareable": True,
                "accessible": False,
            }
        ],
    )

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT local_paths.display_path,
                   shared_directory_roots.monitor_owned,
                   shared_directory_roots.shareable,
                   shared_directory_roots.accessible,
                   shared_directory_roots.enabled,
                   shared_directory_roots.deleted_at_ms
            FROM shared_directory_roots
            JOIN local_paths ON local_paths.id = shared_directory_roots.path_id
            """
        ).fetchall()

    assert rows == [(str(root), 0, 1, 0, 1, None)]


def test_import_known_met_seeds_all_duplicate_paths(tmp_path: Path) -> None:
    roots = [tmp_path / "one", tmp_path / "two"]
    modified_s = 1_700_000_000
    payloads = []
    for root in roots:
        root.mkdir()
        payload = root / "Duplicate.bin"
        payload.write_bytes(b"same")
        os.utime(payload, (modified_s, modified_s))
        payloads.append(payload)
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="Duplicate.bin",
                size_bytes=4,
            )
        ],
    )
    db_path = tmp_path / "metadata.sqlite"
    rust_metadata.create_metadata_db(_rust_repo(), db_path)

    summary = mfc_known_met.import_mfc_known_met_hashes(
        rust_repo=_rust_repo(),
        metadata_db=db_path,
        known_met=known_met,
        shared_roots=roots,
    )

    # A known.met record matching two byte-identical duplicates seeds the shared hash
    # for BOTH paths (same content -> same ed2k hash) instead of being discarded.
    assert summary["matchedRecords"] == 1
    assert summary["duplicateRecords"] == 1
    assert summary["importedRecords"] == 1
    assert summary["importedSourcePaths"] == 2
    assert summary["skipped"]["no_path_match"] == 0
    with sqlite3.connect(db_path) as conn:
        seeded = {
            row[0]
            for row in conn.execute(
                """
                SELECT local_paths.display_path
                FROM shared_file_sources
                JOIN local_paths ON local_paths.id = shared_file_sources.path_id
                """
            )
        }
    assert seeded == {str(payloads[0]), str(payloads[1])}


def test_import_known_met_reports_missing_path_match(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=1_700_000_000,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="Missing.bin",
                size_bytes=4,
            )
        ],
    )

    summary = mfc_known_met.import_mfc_known_met_hashes(
        rust_repo=_rust_repo(),
        metadata_db=tmp_path / "metadata.sqlite",
        known_met=known_met,
        shared_roots=[shared],
        dry_run=True,
    )

    assert summary["matchedRecords"] == 0
    assert summary["skipped"]["no_path_match"] == 1


def test_scan_shared_file_candidates_respects_flat_and_recursive_roots(tmp_path: Path) -> None:
    flat = tmp_path / "flat"
    recursive = tmp_path / "recursive"
    flat_child = flat / "child"
    recursive_child = recursive / "child"
    flat_child.mkdir(parents=True)
    recursive_child.mkdir(parents=True)
    flat_payload = flat / "Flat.bin"
    flat_nested = flat_child / "FlatNested.bin"
    recursive_payload = recursive / "Recursive.bin"
    recursive_nested = recursive_child / "RecursiveNested.bin"
    for payload in [flat_payload, flat_nested, recursive_payload, recursive_nested]:
        payload.write_bytes(payload.name.encode("utf-8"))

    candidates = mfc_known_met.scan_shared_file_candidates(
        [
            {"path": str(flat), "recursive": False},
            {"path": str(recursive), "recursive": True},
        ]
    )

    scanned = {candidate.path for candidate in candidates}
    assert flat_payload in scanned
    assert flat_nested not in scanned
    assert recursive_payload in scanned
    assert recursive_nested in scanned


def test_import_mfc_shared_file_rows_uses_exact_rest_path(tmp_path: Path) -> None:
    root = tmp_path / "share"
    root.mkdir()
    duplicate = tmp_path / "other"
    duplicate.mkdir()
    payload = root / "Duplicate.bin"
    payload.write_bytes(b"same")
    other_payload = duplicate / "Duplicate.bin"
    other_payload.write_bytes(b"same")
    modified_s = 1_700_000_000
    os.utime(payload, (modified_s, modified_s))
    os.utime(other_payload, (modified_s, modified_s))
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="Duplicate.bin",
                size_bytes=payload.stat().st_size,
            )
        ],
    )
    db_path = tmp_path / "metadata.sqlite"
    rust_metadata.create_metadata_db(_rust_repo(), db_path)

    summary = mfc_known_met.import_mfc_shared_file_rows_hashes(
        rust_repo=_rust_repo(),
        metadata_db=db_path,
        known_met=known_met,
        shared_file_rows=[
            {
                "hash": "00112233445566778899aabbccddeeff",
                "name": "Duplicate.bin",
                "path": str(payload),
                "sizeBytes": payload.stat().st_size,
                "priority": "auto",
                "autoUploadPriority": True,
                "allTimeTransferred": 123456789,
            }
        ],
        shared_roots=[root],
    )

    assert summary["importedRows"] == 1
    assert summary["skipped"]["path_outside_shared_roots"] == 0
    manifest = rust_metadata.read_transfer_manifest(db_path, "00112233445566778899aabbccddeeff")
    assert manifest is not None
    assert manifest["completed"] is True
    assert manifest["source_path"] == str(payload)
    assert manifest["source_mtime_ms"] // 1000 == modified_s
    assert manifest["upload_priority"] == "normal"
    assert manifest["auto_upload_priority"] is False
    assert manifest["all_time_uploaded_bytes"] == 0
    with sqlite3.connect(db_path) as conn:
        source_row = conn.execute(
            """
            SELECT shared_file_sources.file_size, shared_file_sources.source_mtime_ms
            FROM shared_file_sources
            JOIN local_paths ON local_paths.id = shared_file_sources.path_id
            WHERE local_paths.display_path = ?
            """,
            (str(payload),),
        ).fetchone()
        piece_rows = conn.execute("SELECT count(*) FROM transfer_pieces").fetchone()[0]
        range_row = conn.execute(
            """
            SELECT start_offset, end_offset
            FROM verified_ranges
            """
        ).fetchone()
    assert source_row == (payload.stat().st_size, manifest["source_mtime_ms"])
    assert piece_rows == 0
    assert range_row == (0, payload.stat().st_size)


def test_import_mfc_shared_file_rows_rejects_outside_shared_roots(tmp_path: Path) -> None:
    root = tmp_path / "share"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    payload = outside / "File.bin"
    payload.write_bytes(b"same")
    modified_s = 1_700_000_000
    os.utime(payload, (modified_s, modified_s))
    known_met = tmp_path / "known.met"
    _write_known_met(
        known_met,
        [
            _known_record(
                modified_s=modified_s,
                ed2k_hash="00112233445566778899aabbccddeeff",
                name="File.bin",
                size_bytes=payload.stat().st_size,
            )
        ],
    )

    summary = mfc_known_met.import_mfc_shared_file_rows_hashes(
        rust_repo=_rust_repo(),
        metadata_db=tmp_path / "metadata.sqlite",
        known_met=known_met,
        shared_file_rows=[
            {
                "hash": "00112233445566778899aabbccddeeff",
                "name": "File.bin",
                "path": str(payload),
                "sizeBytes": payload.stat().st_size,
            }
        ],
        shared_roots=[root],
        dry_run=True,
    )

    assert summary["matchedRows"] == 0
    assert summary["skipped"]["path_outside_shared_roots"] == 1


def test_path_root_membership_uses_parent_set_without_prefix_false_positive(tmp_path: Path) -> None:
    root = tmp_path / "share"
    nested = root / "nested"
    sibling_prefix = tmp_path / "share-sibling"
    nested.mkdir(parents=True)
    sibling_prefix.mkdir()

    roots = {mfc_known_met._canonical_existing_root(root)}

    assert mfc_known_met._path_is_under_root_set(nested / "File.bin", roots) is True
    assert mfc_known_met._path_is_under_root_set(sibling_prefix / "File.bin", roots) is False


def test_import_mfc_shared_file_rows_requires_known_met_hashset(tmp_path: Path) -> None:
    root = tmp_path / "share"
    root.mkdir()
    payload = root / "File.bin"
    payload.write_bytes(b"same")
    known_met = tmp_path / "known.met"
    _write_known_met(known_met, [])

    summary = mfc_known_met.import_mfc_shared_file_rows_hashes(
        rust_repo=_rust_repo(),
        metadata_db=tmp_path / "metadata.sqlite",
        known_met=known_met,
        shared_file_rows=[
            {
                "hash": "00112233445566778899aabbccddeeff",
                "name": "File.bin",
                "path": str(payload),
                "sizeBytes": payload.stat().st_size,
            }
        ],
        shared_roots=[root],
        dry_run=True,
    )

    assert summary["matchedRows"] == 0
    assert summary["skipped"]["missing_known_met_entry"] == 1


def test_load_shared_file_rows_json_accepts_rest_envelope(tmp_path: Path) -> None:
    inventory = tmp_path / "shared-files.json"
    inventory.write_text(
        '{"data":{"items":[{"hash":"00112233445566778899aabbccddeeff","path":"C:/x","sizeBytes":1}]}}',
        encoding="utf-8",
    )

    rows = mfc_known_met.load_shared_file_rows_json(inventory)

    assert rows == [{"hash": "00112233445566778899aabbccddeeff", "path": "C:/x", "sizeBytes": 1}]


def test_normal_windows_display_path_removes_verbatim_prefix() -> None:
    assert mfc_known_met.normal_windows_display_path(r"\\?\F:\share\file.bin") == r"F:\share\file.bin"
    assert mfc_known_met.normal_windows_display_path(r"\\?\UNC\host\share\file.bin") == r"\\host\share\file.bin"
