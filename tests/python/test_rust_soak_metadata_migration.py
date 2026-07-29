from __future__ import annotations

import sqlite3
from pathlib import Path

from emule_test_harness import rust_metadata
from emule_test_harness.rust_soak_metadata_migration import (
    migrate_to_current,
    migrate_v16_to_v17,
)


def workspace_root() -> Path:
    return Path(__file__).resolve().parents[4]


def rust_repo() -> Path:
    return workspace_root() / "repos" / "emulebb-rust"


def make_v15_db(path: Path) -> None:
    schema_id, _schema_version = rust_metadata._schema_marker(rust_repo())
    with sqlite3.connect(path) as conn:
        conn.executescript(rust_metadata._schema_sql(rust_repo()))
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, 15, 0)",
            (schema_id,),
        )
        conn.execute(
            "INSERT INTO profile(id, uuid, created_by, created_at_ms, updated_at_ms) VALUES (1, 'profile', 'test', 0, 0)"
        )
        conn.execute(
            "ALTER TABLE shared_directory_roots ADD COLUMN recursive INTEGER NOT NULL DEFAULT 0 CHECK(recursive IN (0, 1))"
        )
        conn.execute(
            """
            INSERT INTO local_paths(
                display_path, native_path, canonical_display_path, normalized_key,
                platform, file_identity_kind, file_identity, size_bytes, mtime_ms,
                last_stat_ms
            )
            VALUES ('C:/share', X'433A2F7368617265', 'C:/share', 'c:/share',
                    'windows', NULL, NULL, NULL, NULL, NULL)
            """
        )
        path_id = conn.execute("SELECT id FROM local_paths").fetchone()[0]
        conn.execute(
            """
            INSERT INTO shared_directory_roots(
                path_id, recursive, monitor_owned, shareable, accessible,
                enabled, last_scan_ms, created_at_ms, deleted_at_ms
            )
            VALUES (?, 1, 0, 1, 1, 1, 123, 0, NULL)
            """,
            (path_id,),
        )
        conn.commit()


def make_v16_db_with_old_priority_check(path: Path) -> None:
    schema_id, _schema_version = rust_metadata._schema_marker(rust_repo())
    old_schema = rust_metadata._schema_sql(rust_repo()).replace(
        "'auto', 'not-published', 'verylow', 'low', 'normal', 'high', 'release'",
        "'auto', 'verylow', 'low', 'normal', 'high', 'release'",
    )
    with sqlite3.connect(path) as conn:
        conn.executescript(old_schema)
        conn.execute(
            "INSERT INTO metadata_schema(schema_id, schema_version, created_at_ms) VALUES (?, 16, 0)",
            (schema_id,),
        )
        conn.execute(
            """
            INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name, upload_priority,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (zeroblob(16), 1, 'sample.bin', 'normal', 0, 0, 0)
            """
        )
        conn.commit()


def assert_known_files_accepts_not_published(db_path: Path) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name, upload_priority,
                first_seen_ms, last_seen_ms, updated_at_ms
            )
            VALUES (X'11111111111111111111111111111111', 1, 'hidden.bin', 'not-published', 0, 0, 0)
            """
        )
        conn.commit()


def test_migrates_v15_soak_metadata_to_current_shape(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    make_v15_db(db_path)
    _schema_id, current_schema_version = rust_metadata._schema_marker(rust_repo())

    result = migrate_to_current(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "migrated-to-current"
    assert [step["action"] for step in result["steps"]] == [
        "migrated-v15-to-v16",
        "migrated-v16-to-v17",
        "finalized-v17-to-current",
    ]
    assert all(Path(str(step["backup"])).is_file() for step in result["steps"])
    with sqlite3.connect(db_path) as conn:
        assert (
            conn.execute("SELECT schema_version FROM metadata_schema").fetchone()[0]
            == current_schema_version
        )
        columns = [
            row[1] for row in conn.execute("PRAGMA table_info(shared_directory_roots)")
        ]
        assert "recursive" not in columns
        assert (
            conn.execute("SELECT count(*) FROM imported_known_files").fetchone()[0] == 0
        )
        assert (
            conn.execute("SELECT count(*) FROM shared_directory_roots").fetchone()[0]
            == 1
        )
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert_known_files_accepts_not_published(db_path)


def test_migrates_v16_known_files_priority_constraint_to_v17(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    make_v16_db_with_old_priority_check(db_path)

    result = migrate_v16_to_v17(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "migrated-v16-to-v17"
    assert Path(str(result["backup"])).is_file()
    with sqlite3.connect(db_path) as conn:
        assert (
            conn.execute("SELECT schema_version FROM metadata_schema").fetchone()[0]
            == 17
        )
        assert conn.execute("SELECT count(*) FROM known_files").fetchone()[0] == 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    assert_known_files_accepts_not_published(db_path)


def test_current_schema_is_noop(tmp_path: Path) -> None:
    db_path = tmp_path / "emulebb-rust-metadata.db"
    rust_metadata.create_metadata_db(rust_repo(), db_path)

    result = migrate_to_current(
        db_path=db_path, rust_repo=rust_repo(), backup_dir=tmp_path
    )

    assert result["action"] == "noop-current"
    assert result["steps"] == []
