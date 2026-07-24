"""Helpers to seed the eMuleBB Rust profile metadata store for harness scenarios.

The Rust client persists its search index and ED2K transfer manifests in a single
SQLite database (``<profileDir>/emulebb-rust-metadata.db``). Harness scenarios
that need to stage profile settings or prior client state seed that database
directly before launching the client.

To avoid duplicating the Rust schema in Python, these helpers read the canonical
``schema.sql`` and schema marker straight from the ``emulebb-metadata`` crate, so a
schema change in the client is picked up automatically. Only the small set of seed
``INSERT`` statements is coupled to specific tables.
"""

from __future__ import annotations

import re
import json
import sqlite3
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any

ED2K_PART_SIZE = 9_728_000
RUST_PROFILE_METADATA_FILE = "emulebb-rust-metadata.db"


def _metadata_src_dir(rust_repo: Path) -> Path:
    return rust_repo / "crates" / "emulebb-metadata" / "src"


def _schema_sql(rust_repo: Path) -> str:
    return (_metadata_src_dir(rust_repo) / "schema.sql").read_text(encoding="utf-8")


def _schema_marker(rust_repo: Path) -> tuple[str, int]:
    text = (_metadata_src_dir(rust_repo) / "schema.rs").read_text(encoding="utf-8")
    schema_id = re.search(r'SCHEMA_ID:\s*&str\s*=\s*"([^"]+)"', text)
    schema_version = re.search(r"SCHEMA_VERSION:\s*i64\s*=\s*(\d+)", text)
    if schema_id is None or schema_version is None:
        raise RuntimeError("could not parse SCHEMA_ID/SCHEMA_VERSION from emulebb-metadata schema.rs")
    return schema_id.group(1), int(schema_version.group(1))


def normalize_search_text(value: str) -> str:
    """Mirror ``emulebb_metadata::text::normalize_search_text`` for FTS seed rows."""

    folded = "".join(ch.lower() for ch in unicodedata.normalize("NFKC", value))
    spaced = "".join(ch if ch.isalnum() else " " for ch in folded)
    return " ".join(spaced.split())


def _now_ms() -> int:
    return int(time.time() * 1000)


def create_metadata_db(rust_repo: Path, db_path: Path) -> None:
    """Create ``emulebb-rust-metadata.db`` with the canonical schema and marker row.

    The Rust ``MetadataStore`` keeps a pre-existing database only when the
    ``metadata_schema`` marker matches its compiled ``SCHEMA_ID``/``SCHEMA_VERSION``;
    otherwise it resets every table. Writing the marker here lets seeded rows survive
    daemon startup.
    """

    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema_id, schema_version = _schema_marker(rust_repo)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_schema_sql(rust_repo))
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, ?, ?)",
            (schema_id, schema_version, _now_ms()),
        )
        conn.commit()


def put_setting_json(db_path: Path, section: str, key: str, value: object) -> None:
    """Upsert one Rust profile settings row using the canonical JSON row shape."""

    if not section.strip():
        raise ValueError("settings section must not be empty")
    if not key.strip():
        raise ValueError("settings key must not be empty")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO settings(section, key, value_json, updated_at_ms)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(section, key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at_ms = excluded.updated_at_ms
            """,
            (section, key, json.dumps(value), _now_ms()),
        )
        conn.commit()


def replace_settings_section(db_path: Path, section: str, values: dict[str, object]) -> None:
    """Replace one Rust settings section with scalar JSON setting rows."""

    if not section.strip():
        raise ValueError("settings section must not be empty")
    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM settings WHERE section = ?", (section,))
        for key, value in sorted(values.items()):
            if not key.strip():
                raise ValueError("settings key must not be empty")
            conn.execute(
                """
                INSERT INTO settings(section, key, value_json, updated_at_ms)
                VALUES (?, ?, ?, ?)
                """,
                (section, key, json.dumps(value), now),
            )
        conn.commit()


def replace_kad_bootstrap_endpoints(db_path: Path, endpoints: list[str]) -> None:
    """Replace the ordered Rust Kad bootstrap endpoint list."""

    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM kad_bootstrap_endpoints")
        for position, endpoint in enumerate(endpoints):
            if not endpoint.strip():
                raise ValueError("Kad bootstrap endpoint must not be empty")
            conn.execute(
                """
                INSERT INTO kad_bootstrap_endpoints(position, endpoint, updated_at_ms)
                VALUES (?, ?, ?)
                """,
                (position, endpoint, now),
            )
        conn.commit()


def seed_local_user_hash(db_path: Path, user_hash: bytes) -> None:
    """Seed the Rust ED2K user-hash identity from stock ``preferences.dat`` bytes."""

    if len(user_hash) != 16:
        raise ValueError("ED2K user hash must be exactly 16 bytes")
    normalized = bytearray(user_hash)
    normalized[5] = 0x0E
    normalized[14] = 0x6F
    if _user_hash_is_bad(bytes(normalized)):
        raise ValueError("ED2K user hash must not be an eMule bad hash")
    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO local_identities(
                identity_kind, public_identity, private_secret, created_at_ms, updated_at_ms
            )
            VALUES ('ed2k-user-hash', ?, NULL, ?, ?)
            ON CONFLICT(identity_kind) DO UPDATE SET
                public_identity = excluded.public_identity,
                private_secret = NULL,
                updated_at_ms = excluded.updated_at_ms
            """,
            (bytes(normalized), now, now),
        )
        conn.commit()


def _user_hash_is_bad(user_hash: bytes) -> bool:
    lo = int.from_bytes(user_hash[:8], "little")
    hi = int.from_bytes(user_hash[8:], "little")
    return (lo & 0xFFFF_00FF_FFFF_FFFF) == 0 and (hi & 0xFF00_FFFF_FFFF_FFFF) == 0


def seed_server(db_path: Path, server: dict[str, object]) -> None:
    """Seed one enabled ED2K server row into the Rust SQLite profile."""

    address = str(server.get("host") or server.get("address") or "").strip()
    port = int(server.get("port") or 0)
    if not address or not (1 <= port <= 65535):
        raise ValueError("Rust server seed requires host/address and port.")
    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO servers(
                address, port, name, description, server_priority, static_server,
                enabled, failed_count, ping_ms, users, files, soft_files, hard_files,
                version, obfuscation_tcp_port, udp_flags, first_seen_ms, last_seen_ms, deleted_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, 0, 0, 0, 0, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(address, port) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                server_priority = excluded.server_priority,
                static_server = excluded.static_server,
                enabled = excluded.enabled,
                version = excluded.version,
                obfuscation_tcp_port = excluded.obfuscation_tcp_port,
                udp_flags = excluded.udp_flags,
                last_seen_ms = excluded.last_seen_ms,
                deleted_at_ms = NULL
            """,
            (
                address,
                port,
                str(server.get("name") or ""),
                str(server.get("description") or ""),
                str(server.get("serverPriority") or "normal"),
                1 if bool(server.get("staticServer", True)) else 0,
                1 if bool(server.get("enabled", True)) else 0,
                str(server.get("version") or ""),
                _optional_int(server.get("obfuscationPortTcp") or server.get("obfuscationTcpPort")),
                _optional_int(server.get("udpFlags")),
                now,
                now,
            ),
        )
        conn.commit()


def clear_servers(db_path: Path) -> None:
    """Remove persisted ED2K server rows from a Rust SQLite profile."""

    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM servers")
        conn.commit()


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return int(value)


def seed_indexed_file(
    db_path: Path,
    *,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    content_type: str = "archive",
    availability_score: int = 0,
) -> None:
    """Seed a harvested search-index entry (mirrors ``MetadataStore::upsert_indexed_file``)."""

    hash_blob = bytes.fromhex(ed2k_hash)
    normalized = normalize_search_text(name)
    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name,
                content_type, availability_score, first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ed2k_hash) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                display_name = excluded.display_name,
                content_type = excluded.content_type,
                availability_score = max(known_files.availability_score, excluded.availability_score),
                last_seen_ms = excluded.last_seen_ms,
                updated_at_ms = excluded.updated_at_ms
            """,
            (hash_blob, size_bytes, name, content_type, availability_score, now, now, now),
        )
        known_file_id = conn.execute(
            "SELECT id FROM known_files WHERE ed2k_hash = ?", (hash_blob,)
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO file_names(known_file_id, name, normalized_name, seen_count, first_seen_ms, last_seen_ms)
            VALUES (?, ?, ?, 1, ?, ?)
            ON CONFLICT(known_file_id, normalized_name) DO UPDATE SET
                name = excluded.name,
                seen_count = file_names.seen_count + 1,
                last_seen_ms = excluded.last_seen_ms
            """,
            (known_file_id, name, normalized, now, now),
        )
        conn.commit()


def seed_transfer_manifest(
    db_path: Path,
    *,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    piece_size: int,
    completed: bool = False,
    md4_hashset_acquired: bool = False,
    md4_hashset: list[str] | None = None,
    aich_hashset_acquired: bool = False,
    aich_root: str | None = None,
    aich_hashset: list[str] | None = None,
    sources: list[dict] | None = None,
    control_state: str | None = None,
    upload_priority: str = "normal",
    auto_upload_priority: bool = False,
    all_time_uploaded_bytes: int = 0,
    all_time_upload_requests: int = 0,
    all_time_upload_accepts: int = 0,
    last_upload_request_ms: int = 0,
    comment: str = "",
    rating: int = 0,
    source_path: str | None = None,
    source_mtime_ms: int | None = None,
) -> None:
    """Seed a full ED2K transfer manifest (mirrors ``MetadataStore::upsert_transfer_manifest``).

    ``sources`` items are dicts with ``ip``, ``tcp_port`` and optional ``user_hash`` (hex).
    ``md4_hashset``/``aich_hashset`` are lists of lowercase hex part hashes.
    """

    md4_hashset = md4_hashset or []
    aich_hashset = aich_hashset or []
    sources = sources or []
    hash_blob = bytes.fromhex(ed2k_hash)
    piece_count = (size_bytes + piece_size - 1) // piece_size if size_bytes and piece_size else 0
    if completed:
        visible_state = "completed"
    elif control_state is not None:
        visible_state = "controlled"
    else:
        visible_state = "queued"
    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        source_path_id = _optional_local_path_id(conn, source_path, now)
        conn.execute(
            """
            INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name,
                part_size, part_count, completed, md4_hashset_acquired,
                aich_hashset_acquired, aich_root, upload_priority,
                auto_upload_priority, comment, rating, all_time_uploaded_bytes,
                all_time_upload_requests, all_time_upload_accepts,
                last_upload_request_ms,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ed2k_hash) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                display_name = excluded.display_name,
                part_size = excluded.part_size,
                part_count = excluded.part_count,
                completed = excluded.completed,
                md4_hashset_acquired = excluded.md4_hashset_acquired,
                aich_hashset_acquired = excluded.aich_hashset_acquired,
                aich_root = excluded.aich_root,
                upload_priority = excluded.upload_priority,
                auto_upload_priority = excluded.auto_upload_priority,
                comment = excluded.comment,
                rating = excluded.rating,
                all_time_uploaded_bytes = excluded.all_time_uploaded_bytes,
                all_time_upload_requests = excluded.all_time_upload_requests,
                all_time_upload_accepts = excluded.all_time_upload_accepts,
                last_upload_request_ms = excluded.last_upload_request_ms,
                last_seen_ms = excluded.last_seen_ms,
                updated_at_ms = excluded.updated_at_ms
            """,
            (
                hash_blob,
                size_bytes,
                name,
                piece_size,
                piece_count,
                1 if completed else 0,
                1 if md4_hashset_acquired else 0,
                1 if aich_hashset_acquired else 0,
                bytes.fromhex(aich_root) if aich_root else None,
                upload_priority,
                1 if auto_upload_priority else 0,
                comment,
                rating,
                all_time_uploaded_bytes,
                all_time_upload_requests,
                all_time_upload_accepts,
                last_upload_request_ms,
                now,
                now,
                now,
            ),
        )
        known_file_id = conn.execute(
            "SELECT id FROM known_files WHERE ed2k_hash = ?", (hash_blob,)
        ).fetchone()[0]
        conn.execute(
            """
            INSERT INTO transfers(
                known_file_id, visible_state, control_state, download_priority,
                payload_directory, source_path_id, source_mtime_ms,
                created_at_ms, updated_at_ms, completed_at_ms
            )
            VALUES (?, ?, ?, 'normal', ?, ?, ?, ?, ?, ?)
            ON CONFLICT(known_file_id) DO UPDATE SET
                visible_state = excluded.visible_state,
                control_state = excluded.control_state,
                download_priority = excluded.download_priority,
                payload_directory = excluded.payload_directory,
                source_path_id = excluded.source_path_id,
                source_mtime_ms = excluded.source_mtime_ms,
                updated_at_ms = excluded.updated_at_ms,
                completed_at_ms = excluded.completed_at_ms,
                removed_at_ms = NULL
            """,
            (
                known_file_id,
                visible_state,
                control_state,
                ed2k_hash,
                source_path_id,
                source_mtime_ms,
                now,
                now,
                now if completed else None,
            ),
        )
        transfer_id = conn.execute(
            "SELECT id FROM transfers WHERE known_file_id = ?", (known_file_id,)
        ).fetchone()[0]
        if source_path_id is not None:
            conn.execute(
                """
                INSERT INTO shared_file_sources(
                    known_file_id, path_id, file_size, source_mtime_ms,
                    created_at_ms, updated_at_ms
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(path_id) DO UPDATE SET
                    known_file_id = excluded.known_file_id,
                    file_size = excluded.file_size,
                    source_mtime_ms = excluded.source_mtime_ms,
                    updated_at_ms = excluded.updated_at_ms
                """,
                (known_file_id, source_path_id, size_bytes, source_mtime_ms, now, now),
            )
            conn.execute("DELETE FROM shared_file_scan_failures WHERE path_id = ?", (source_path_id,))
        conn.execute("DELETE FROM transfer_pieces WHERE transfer_id = ?", (transfer_id,))
        conn.execute("DELETE FROM ed2k_part_hashes WHERE known_file_id = ?", (known_file_id,))
        conn.execute("DELETE FROM aich_part_hashes WHERE known_file_id = ?", (known_file_id,))
        conn.execute("DELETE FROM verified_ranges WHERE known_file_id = ?", (known_file_id,))
        conn.execute("DELETE FROM transfer_sources WHERE transfer_id = ?", (transfer_id,))
        for piece_index in range(piece_count):
            state = "Verified" if completed else "Missing"
            written = expected_piece_length(size_bytes, piece_size, piece_index) if completed else 0
            conn.execute(
                """
                INSERT INTO transfer_pieces(transfer_id, piece_index, state, bytes_written, updated_at_ms)
                VALUES (?, ?, ?, ?, ?)
                """,
                (transfer_id, piece_index, state, written, now),
            )
        for index, part_hash in enumerate(md4_hashset):
            conn.execute(
                "INSERT INTO ed2k_part_hashes(known_file_id, part_index, md4_hash) VALUES (?, ?, ?)",
                (known_file_id, index, bytes.fromhex(part_hash)),
            )
        for index, part_hash in enumerate(aich_hashset):
            conn.execute(
                "INSERT INTO aich_part_hashes(known_file_id, part_index, aich_hash) VALUES (?, ?, ?)",
                (known_file_id, index, bytes.fromhex(part_hash)),
            )
        for source in sources:
            user_hash = source.get("user_hash")
            conn.execute(
                """
                INSERT INTO transfer_sources(transfer_id, ip, tcp_port, user_hash, first_seen_ms, last_seen_ms)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    transfer_id,
                    source["ip"],
                    source["tcp_port"],
                    bytes.fromhex(user_hash) if user_hash else None,
                    now,
                    now,
                ),
            )
        if completed:
            conn.execute(
                """
                INSERT INTO verified_ranges(known_file_id, start_offset, end_offset, created_at_ms)
                VALUES (?, 0, ?, ?)
                """,
                (known_file_id, size_bytes, now),
            )
        conn.commit()


def seed_share_in_place_manifest(
    db_path: Path,
    *,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    source_path: str,
    source_mtime_ms: int,
    md4_hashset: list[str] | None = None,
    aich_root: str | None = None,
    aich_hashset: list[str] | None = None,
    upload_priority: str = "normal",
    auto_upload_priority: bool = False,
    all_time_uploaded_bytes: int = 0,
    all_time_upload_requests: int = 0,
    all_time_upload_accepts: int = 0,
    last_upload_request_ms: int = 0,
) -> None:
    """Seed a completed shared-file manifest that Rust can reload without hashing.

    The row mirrors Rust's local ingest result: completed transfer, verified
    pieces and ranges, original ``source_path``, and source mtime. A later
    shared-directory reload skips hashing only when path, size, and mtime still
    match the scanned file.
    """

    seed_transfer_manifest(
        db_path,
        ed2k_hash=ed2k_hash,
        name=name,
        size_bytes=size_bytes,
        piece_size=ED2K_PART_SIZE,
        completed=True,
        md4_hashset_acquired=True,
        md4_hashset=md4_hashset or [],
        aich_hashset_acquired=aich_root is not None,
        aich_root=aich_root,
        aich_hashset=aich_hashset or [],
        upload_priority=upload_priority,
        auto_upload_priority=auto_upload_priority,
        all_time_uploaded_bytes=all_time_uploaded_bytes,
        all_time_upload_requests=all_time_upload_requests,
        all_time_upload_accepts=all_time_upload_accepts,
        last_upload_request_ms=last_upload_request_ms,
        source_path=source_path,
        source_mtime_ms=source_mtime_ms,
    )


def seed_share_in_place_manifests(
    db_path: Path,
    manifests: list[dict[str, object]],
    *,
    seed_piece_rows: bool = True,
) -> None:
    """Seed many completed share-in-place manifests in one SQLite transaction."""

    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        for manifest in manifests:
            _seed_share_in_place_manifest_conn(
                conn,
                now=now,
                seed_piece_rows=seed_piece_rows,
                **manifest,
            )
        conn.commit()


def seed_shared_directory_roots(db_path: Path, roots: list[dict[str, Any]]) -> None:
    """Seed Rust shared-directory roots before daemon startup.

    Preseeded share-in-place manifests are pruned by Rust's startup reload when
    no shared roots exist yet. Live parity harnesses therefore write the roots
    into metadata before launching the daemon; the later REST patch remains an
    idempotent confirmation of the same desired state.
    """

    now = _now_ms()
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            "UPDATE shared_directory_roots SET deleted_at_ms = ? WHERE deleted_at_ms IS NULL",
            (now,),
        )
        for root in roots:
            path = str(root.get("path") or "")
            if not path.strip("\\"):
                continue
            path_id = _upsert_local_path(conn, path, now)
            conn.execute(
                """
                INSERT INTO shared_directory_roots(
                    path_id, monitor_owned, shareable, accessible,
                    enabled, created_at_ms, deleted_at_ms
                )
                VALUES (?, ?, ?, ?, 1, ?, NULL)
                ON CONFLICT(path_id) DO UPDATE SET
                    monitor_owned = excluded.monitor_owned,
                    shareable = excluded.shareable,
                    accessible = excluded.accessible,
                    enabled = 1,
                    deleted_at_ms = NULL
                """,
                (
                    path_id,
                    1 if root.get("monitorOwned") else 0,
                    1 if root.get("shareable", True) else 0,
                    1 if root.get("accessible", True) else 0,
                    now,
                ),
            )
        conn.commit()


def _seed_share_in_place_manifest_conn(
    conn: sqlite3.Connection,
    *,
    now: int,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    source_path: str,
    source_mtime_ms: int,
    md4_hashset: list[str] | None = None,
    aich_root: str | None = None,
    aich_hashset: list[str] | None = None,
    upload_priority: str = "normal",
    auto_upload_priority: bool = False,
    all_time_uploaded_bytes: int = 0,
    all_time_upload_requests: int = 0,
    all_time_upload_accepts: int = 0,
    last_upload_request_ms: int = 0,
    seed_piece_rows: bool = True,
) -> None:
    md4_hashset = md4_hashset or []
    aich_hashset = aich_hashset or []
    hash_blob = bytes.fromhex(ed2k_hash)
    piece_size = ED2K_PART_SIZE
    piece_count = (size_bytes + piece_size - 1) // piece_size if size_bytes and piece_size else 0
    source_path_id = _upsert_local_path(conn, source_path, now)
    conn.execute(
        """
        INSERT INTO known_files(
            ed2k_hash, size_bytes, display_name,
            part_size, part_count, completed, md4_hashset_acquired,
            aich_hashset_acquired, aich_root, upload_priority,
            auto_upload_priority, all_time_uploaded_bytes,
            all_time_upload_requests, all_time_upload_accepts,
            last_upload_request_ms,
            first_seen_ms, last_seen_ms, updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ed2k_hash) DO UPDATE SET
            size_bytes = excluded.size_bytes,
            display_name = excluded.display_name,
            part_size = excluded.part_size,
            part_count = excluded.part_count,
            completed = excluded.completed,
            md4_hashset_acquired = excluded.md4_hashset_acquired,
            aich_hashset_acquired = excluded.aich_hashset_acquired,
            aich_root = excluded.aich_root,
            upload_priority = excluded.upload_priority,
            auto_upload_priority = excluded.auto_upload_priority,
            all_time_uploaded_bytes = excluded.all_time_uploaded_bytes,
            all_time_upload_requests = excluded.all_time_upload_requests,
            all_time_upload_accepts = excluded.all_time_upload_accepts,
            last_upload_request_ms = excluded.last_upload_request_ms,
            last_seen_ms = excluded.last_seen_ms,
            updated_at_ms = excluded.updated_at_ms
        """,
        (
            hash_blob,
            size_bytes,
            name,
            piece_size,
            piece_count,
            1 if aich_root is not None else 0,
            bytes.fromhex(aich_root) if aich_root else None,
            upload_priority,
            1 if auto_upload_priority else 0,
            all_time_uploaded_bytes,
            all_time_upload_requests,
            all_time_upload_accepts,
            last_upload_request_ms,
            now,
            now,
            now,
        ),
    )
    known_file_id = conn.execute(
        "SELECT id FROM known_files WHERE ed2k_hash = ?", (hash_blob,)
    ).fetchone()[0]
    conn.execute(
        """
        INSERT INTO transfers(
            known_file_id, visible_state, download_priority, payload_directory,
            source_path_id, source_mtime_ms, created_at_ms, updated_at_ms, completed_at_ms
        )
        VALUES (?, 'completed', 'normal', ?, ?, ?, ?, ?, ?)
        ON CONFLICT(known_file_id) DO UPDATE SET
            visible_state = excluded.visible_state,
            download_priority = excluded.download_priority,
            payload_directory = excluded.payload_directory,
            source_path_id = excluded.source_path_id,
            source_mtime_ms = excluded.source_mtime_ms,
            updated_at_ms = excluded.updated_at_ms,
            completed_at_ms = excluded.completed_at_ms,
            removed_at_ms = NULL
        """,
        (known_file_id, ed2k_hash, source_path_id, source_mtime_ms, now, now, now),
    )
    transfer_id = conn.execute(
        "SELECT id FROM transfers WHERE known_file_id = ?", (known_file_id,)
    ).fetchone()[0]
    conn.execute(
        """
        INSERT INTO shared_file_sources(
            known_file_id, path_id, file_size, source_mtime_ms,
            created_at_ms, updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(path_id) DO UPDATE SET
            known_file_id = excluded.known_file_id,
            file_size = excluded.file_size,
            source_mtime_ms = excluded.source_mtime_ms,
            updated_at_ms = excluded.updated_at_ms
        """,
        (known_file_id, source_path_id, size_bytes, source_mtime_ms, now, now),
    )
    conn.execute("DELETE FROM shared_file_scan_failures WHERE path_id = ?", (source_path_id,))
    conn.execute("DELETE FROM transfer_pieces WHERE transfer_id = ?", (transfer_id,))
    conn.execute("DELETE FROM ed2k_part_hashes WHERE known_file_id = ?", (known_file_id,))
    conn.execute("DELETE FROM aich_part_hashes WHERE known_file_id = ?", (known_file_id,))
    conn.execute("DELETE FROM verified_ranges WHERE known_file_id = ?", (known_file_id,))
    if seed_piece_rows:
        for piece_index in range(piece_count):
            conn.execute(
                """
                INSERT INTO transfer_pieces(transfer_id, piece_index, state, bytes_written, updated_at_ms)
                VALUES (?, ?, 'Verified', ?, ?)
                """,
                (transfer_id, piece_index, expected_piece_length(size_bytes, piece_size, piece_index), now),
            )
    for index, part_hash in enumerate(md4_hashset):
        conn.execute(
            "INSERT INTO ed2k_part_hashes(known_file_id, part_index, md4_hash) VALUES (?, ?, ?)",
            (known_file_id, index, bytes.fromhex(part_hash)),
        )
    for index, part_hash in enumerate(aich_hashset):
        conn.execute(
            "INSERT INTO aich_part_hashes(known_file_id, part_index, aich_hash) VALUES (?, ?, ?)",
            (known_file_id, index, bytes.fromhex(part_hash)),
        )
    conn.execute(
        """
        INSERT INTO verified_ranges(known_file_id, start_offset, end_offset, created_at_ms)
        VALUES (?, 0, ?, ?)
        """,
        (known_file_id, size_bytes, now),
    )


def expected_piece_length(file_size: int, piece_size: int, piece_index: int) -> int:
    start = piece_index * piece_size
    return max(0, min(start + piece_size, file_size) - start)


def seed_remembered_source_transfer(
    db_path: Path,
    *,
    ed2k_hash: str,
    name: str,
    size_bytes: int,
    piece_size: int,
    source_ip: str,
    source_tcp_port: int,
    source_user_hash: str | None = None,
) -> None:
    """Seed an incomplete transfer with a single remembered source."""

    seed_transfer_manifest(
        db_path,
        ed2k_hash=ed2k_hash,
        name=name,
        size_bytes=size_bytes,
        piece_size=piece_size,
        sources=[{"ip": source_ip, "tcp_port": source_tcp_port, "user_hash": source_user_hash}],
    )


def read_transfer_manifest(db_path: Path, ed2k_hash: str) -> dict | None:
    """Read a persisted ED2K transfer manifest from the Rust profile metadata DB.

    Mirrors ``MetadataStore::transfer_manifest_by_hash`` and returns the same
    field shape the legacy ``resume-manifest.json`` exposed, so harness checks can
    verify internal hashset/AICH metadata that has no REST surface. Returns
    ``None`` when no known file with that hash exists.
    """

    hash_blob = bytes.fromhex(ed2k_hash)
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT known_files.id, transfers.id, transfers.control_state,
                   known_files.display_name, known_files.size_bytes,
                   coalesce(known_files.part_size, 0),
                   known_files.completed, known_files.md4_hashset_acquired,
                   known_files.aich_hashset_acquired,
                   CASE WHEN known_files.aich_root IS NULL THEN NULL
                        ELSE lower(hex(known_files.aich_root)) END,
                   known_files.upload_priority, known_files.comment, known_files.rating,
                   known_files.auto_upload_priority, known_files.all_time_uploaded_bytes,
                   known_files.all_time_upload_requests,
                   known_files.all_time_upload_accepts,
                   known_files.last_upload_request_ms,
                   source_paths.display_path, transfers.source_mtime_ms
            FROM known_files
            LEFT JOIN transfers ON transfers.known_file_id = known_files.id
            LEFT JOIN local_paths source_paths ON source_paths.id = transfers.source_path_id
            WHERE known_files.ed2k_hash = ?
            """,
            (hash_blob,),
        ).fetchone()
        if row is None:
            return None
        known_file_id = row[0]
        transfer_id = row[1]
        sources = []
        if transfer_id is not None:
            sources = [
                {
                    "ip": src[0],
                    "tcp_port": src[1],
                    "user_hash": src[2],
                }
                for src in conn.execute(
                    """
                    SELECT ip, tcp_port,
                           CASE WHEN user_hash IS NULL THEN NULL ELSE lower(hex(user_hash)) END
                    FROM transfer_sources WHERE transfer_id = ?
                    ORDER BY id
                    """,
                    (transfer_id,),
                )
            ]
        md4_hashset = [
            r[0]
            for r in conn.execute(
                "SELECT lower(hex(md4_hash)) FROM ed2k_part_hashes WHERE known_file_id = ? ORDER BY part_index",
                (known_file_id,),
            )
        ]
        aich_hashset = [
            r[0]
            for r in conn.execute(
                "SELECT lower(hex(aich_hash)) FROM aich_part_hashes WHERE known_file_id = ? ORDER BY part_index",
                (known_file_id,),
            )
        ]
    return {
        "file_hash": ed2k_hash.lower(),
        "control_state": row[2],
        "canonical_name": row[3],
        "file_size": row[4],
        "piece_size": row[5],
        "completed": bool(row[6]),
        "md4_hashset_acquired": bool(row[7]),
        "aich_hashset_acquired": bool(row[8]),
        "aich_root": row[9],
        "upload_priority": row[10],
        "comment": row[11],
        "rating": row[12],
        "auto_upload_priority": bool(row[13]),
        "all_time_uploaded_bytes": row[14],
        "all_time_upload_requests": row[15],
        "all_time_upload_accepts": row[16],
        "last_upload_request_ms": row[17],
        "source_path": row[18],
        "source_mtime_ms": row[19],
        "md4_hashset": md4_hashset,
        "aich_hashset": aich_hashset,
        "sources": sources,
    }


def _optional_local_path_id(conn: sqlite3.Connection, display_path: str | None, now: int) -> int | None:
    if display_path is None:
        return None
    return _upsert_local_path(conn, display_path, now)


def _upsert_local_path(conn: sqlite3.Connection, display_path: str, now: int) -> int:
    normalized_key = normalize_path_key(display_path)
    platform = current_platform()
    conn.execute(
        """
        INSERT INTO local_paths(
            display_path, native_path, canonical_display_path, normalized_key,
            platform, last_stat_ms
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(platform, normalized_key) DO UPDATE SET
            display_path = excluded.display_path,
            native_path = excluded.native_path,
            canonical_display_path = excluded.canonical_display_path,
            last_stat_ms = excluded.last_stat_ms
        """,
        (display_path, display_path.encode(), display_path, normalized_key, platform, now),
    )
    return conn.execute(
        "SELECT id FROM local_paths WHERE platform = ? AND normalized_key = ?",
        (platform, normalized_key),
    ).fetchone()[0]


def normalize_path_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    if current_platform() == "windows":
        return "".join(ch.lower() for ch in normalized)
    return normalized


def current_platform() -> str:
    if sys.platform == "darwin":
        return "macos"
    if sys.platform == "win32":
        return "windows"
    return "unix"
