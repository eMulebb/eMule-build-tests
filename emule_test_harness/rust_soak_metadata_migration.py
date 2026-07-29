"""One-off Rust soak metadata migrations outside the Rust product.

These helpers are for operator-owned persistent soak profiles only. The Rust
client itself stays current-schema-only and must not carry legacy schema
branches or in-product migrations.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path

from . import rust_metadata
from .paths import get_required_emule_workspace_root, get_workspace_output_root

FROM_SCHEMA_VERSION = 15
V16_SCHEMA_VERSION = 16
V17_SCHEMA_VERSION = 17
SCHEMA = "emulebb-build-tests.rust-soak-metadata-migration.v1"
SHARED_ROOT_COLUMNS = (
    "id",
    "path_id",
    "monitor_owned",
    "shareable",
    "accessible",
    "enabled",
    "last_scan_ms",
    "created_at_ms",
    "deleted_at_ms",
)
KNOWN_FILES_COLUMNS = (
    "id",
    "ed2k_hash",
    "size_bytes",
    "display_name",
    "content_type",
    "part_size",
    "part_count",
    "completed",
    "md4_hashset_acquired",
    "aich_hashset_acquired",
    "aich_root",
    "upload_priority",
    "auto_upload_priority",
    "comment",
    "rating",
    "availability_score",
    "all_time_uploaded_bytes",
    "all_time_upload_requests",
    "all_time_upload_accepts",
    "last_upload_request_ms",
    "first_seen_ms",
    "last_seen_ms",
    "updated_at_ms",
)


def default_rust_repo() -> Path:
    return get_required_emule_workspace_root() / "repos" / "emulebb-rust"


def default_metadata_db() -> Path:
    return (
        get_workspace_output_root()
        / "soak"
        / "rust-runtime"
        / rust_metadata.RUST_PROFILE_METADATA_FILE
    )


def schema_marker(db_path: Path, schema_id: str) -> int | None:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT schema_version FROM metadata_schema WHERE schema_id = ?",
            (schema_id,),
        ).fetchone()
    return int(row[0]) if row else None


def table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")')]


def extract_create_table(schema_sql: str, table: str) -> str:
    start_token = f"CREATE TABLE {table} ("
    start = schema_sql.find(start_token)
    if start < 0:
        raise RuntimeError(f"current Rust schema does not define {table}")
    end = schema_sql.find("\n);", start)
    if end < 0:
        raise RuntimeError(
            f"current Rust schema table definition is truncated for {table}"
        )
    return schema_sql[start : end + 3]


def current_shared_roots_table_sql(rust_repo: Path, table_name: str) -> str:
    ddl = extract_create_table(
        rust_metadata._schema_sql(rust_repo), "shared_directory_roots"
    )
    return ddl.replace(
        "CREATE TABLE shared_directory_roots", f"CREATE TABLE {table_name}", 1
    )


def backup_database(db_path: Path, backup_dir: Path | None, label: str) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    target_dir = backup_dir or db_path.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    backup_path = target_dir / f"{db_path.stem}.backup-{label}-{stamp}{db_path.suffix}"
    if backup_path.exists():
        raise RuntimeError(f"backup path already exists: {backup_path}")
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as source:
        with sqlite3.connect(backup_path) as backup:
            source.backup(backup)
    return backup_path


def migrate_v15_to_v16(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    if not db_path.is_file():
        raise RuntimeError(f"metadata database does not exist: {db_path}")

    schema_id, _current_version = rust_metadata._schema_marker(rust_repo)

    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        before_version = schema_marker(db_path, schema_id)
        if before_version is None:
            raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
        columns = table_columns(conn, "shared_directory_roots")
        row_count = int(
            conn.execute("SELECT count(*) FROM shared_directory_roots").fetchone()[0]
        )

    if before_version >= V16_SCHEMA_VERSION and "recursive" not in columns:
        return {
            "schema": SCHEMA,
            "action": "noop-v16-shape-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "schemaVersion": before_version,
            "sharedDirectoryRoots": row_count,
        }
    if before_version != FROM_SCHEMA_VERSION or "recursive" not in columns:
        raise RuntimeError(
            "metadata DB is not the bounded v15 soak profile shape "
            f"(schemaVersion={before_version}, columns={columns})"
        )
    if dry_run:
        return {
            "schema": SCHEMA,
            "action": "would-migrate-v15-to-v16",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": FROM_SCHEMA_VERSION,
            "toSchemaVersion": V16_SCHEMA_VERSION,
            "sharedDirectoryRoots": row_count,
        }

    backup_path = backup_database(db_path, backup_dir, "v15-to-v16")
    temp_table = "shared_directory_roots_v16_migrating"
    column_csv = ", ".join(SHARED_ROOT_COLUMNS)
    create_temp_sql = current_shared_roots_table_sql(rust_repo, temp_table)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(f"DROP TABLE IF EXISTS {temp_table}")
            conn.execute(create_temp_sql)
            conn.execute(
                f"INSERT INTO {temp_table}({column_csv}) "
                f"SELECT {column_csv} FROM shared_directory_roots"
            )
            conn.execute("DROP TABLE shared_directory_roots")
            conn.execute(f"ALTER TABLE {temp_table} RENAME TO shared_directory_roots")
            conn.execute(
                "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                (V16_SCHEMA_VERSION, schema_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.execute("PRAGMA foreign_keys = ON")
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            raise RuntimeError(
                f"foreign key check failed after migration: {fk_issues[:5]}"
            )
        after_columns = table_columns(conn, "shared_directory_roots")
        after_version = schema_marker(db_path, schema_id)

    return {
        "schema": SCHEMA,
        "action": "migrated-v15-to-v16",
        "metadataDb": str(db_path),
        "backup": str(backup_path),
        "schemaId": schema_id,
        "fromSchemaVersion": before_version,
        "toSchemaVersion": after_version,
        "removedColumn": "shared_directory_roots.recursive",
        "sharedDirectoryRoots": row_count,
        "columns": after_columns,
    }


def current_known_files_table_sql(rust_repo: Path, table_name: str) -> str:
    ddl = extract_create_table(rust_metadata._schema_sql(rust_repo), "known_files")
    return ddl.replace("CREATE TABLE known_files", f"CREATE TABLE {table_name}", 1)


def current_imported_known_files_sql(rust_repo: Path) -> str:
    schema_sql = rust_metadata._schema_sql(rust_repo)
    start_token = "CREATE TABLE imported_known_files ("
    end_token = "CREATE TABLE verified_ranges ("
    start = schema_sql.find(start_token)
    end = schema_sql.find(end_token, start)
    if start < 0 or end < 0:
        raise RuntimeError(
            "current Rust schema does not define imported known-file tables"
        )
    return (
        schema_sql[start:end]
        .replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ")
        .replace("CREATE INDEX ", "CREATE INDEX IF NOT EXISTS ")
    )


def known_files_allows_not_published(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'known_files'"
    ).fetchone()
    return bool(row and "not-published" in str(row[0]))


def migrate_v16_to_v17(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    if not db_path.is_file():
        raise RuntimeError(f"metadata database does not exist: {db_path}")

    schema_id, current_version = rust_metadata._schema_marker(rust_repo)
    if current_version < V17_SCHEMA_VERSION:
        raise RuntimeError(
            f"this migration requires Rust schema {V17_SCHEMA_VERSION}+; current schema is {current_version}"
        )

    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        before_version = schema_marker(db_path, schema_id)
        if before_version is None:
            raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
        columns = table_columns(conn, "known_files")
        row_count = int(conn.execute("SELECT count(*) FROM known_files").fetchone()[0])
        already_allows = known_files_allows_not_published(conn)

    if before_version >= V17_SCHEMA_VERSION and already_allows:
        return {
            "schema": SCHEMA,
            "action": "noop-v17-shape-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "schemaVersion": before_version,
            "knownFiles": row_count,
        }
    if before_version != V16_SCHEMA_VERSION or columns != list(KNOWN_FILES_COLUMNS):
        raise RuntimeError(
            "metadata DB is not the bounded v16 soak profile shape "
            f"(schemaVersion={before_version}, columns={columns})"
        )
    if dry_run:
        return {
            "schema": SCHEMA,
            "action": "would-migrate-v16-to-v17",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": V16_SCHEMA_VERSION,
            "toSchemaVersion": V17_SCHEMA_VERSION,
            "knownFiles": row_count,
        }

    backup_path = backup_database(db_path, backup_dir, "v16-to-v17")
    temp_table = "known_files_v17_migrating"
    column_csv = ", ".join(KNOWN_FILES_COLUMNS)
    create_temp_sql = current_known_files_table_sql(rust_repo, temp_table)
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(f"DROP TABLE IF EXISTS {temp_table}")
            conn.execute(create_temp_sql)
            conn.execute(
                f"INSERT INTO {temp_table}({column_csv}) "
                f"SELECT {column_csv} FROM known_files"
            )
            conn.execute("DROP TABLE known_files")
            conn.execute(f"ALTER TABLE {temp_table} RENAME TO known_files")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS known_files_hash_idx ON known_files(ed2k_hash)"
            )
            conn.execute(
                "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                (V17_SCHEMA_VERSION, schema_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.execute("PRAGMA foreign_keys = ON")
        fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_issues:
            raise RuntimeError(
                f"foreign key check failed after migration: {fk_issues[:5]}"
            )
        after_version = schema_marker(db_path, schema_id)
        after_allows = known_files_allows_not_published(conn)

    return {
        "schema": SCHEMA,
        "action": "migrated-v16-to-v17",
        "metadataDb": str(db_path),
        "backup": str(backup_path),
        "schemaId": schema_id,
        "fromSchemaVersion": before_version,
        "toSchemaVersion": after_version,
        "allowedPriority": "not-published",
        "knownFiles": row_count,
        "knownFilesAllowsNotPublished": after_allows,
    }


def migrate_to_current(
    *,
    db_path: Path,
    rust_repo: Path,
    backup_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    db_path = db_path.resolve()
    rust_repo = rust_repo.resolve()
    schema_id, current_version = rust_metadata._schema_marker(rust_repo)
    before_version = schema_marker(db_path, schema_id)
    if before_version is None:
        raise RuntimeError(f"metadata_schema row is missing for {schema_id}")
    original_version = before_version
    steps: list[dict[str, object]] = []

    if before_version == current_version:
        return {
            "schema": SCHEMA,
            "action": "noop-current",
            "metadataDb": str(db_path),
            "schemaId": schema_id,
            "fromSchemaVersion": original_version,
            "toSchemaVersion": current_version,
            "steps": steps,
        }

    if before_version == FROM_SCHEMA_VERSION:
        result = migrate_v15_to_v16(
            db_path=db_path,
            rust_repo=rust_repo,
            backup_dir=backup_dir,
            dry_run=dry_run,
        )
        steps.append(result)
        if dry_run:
            return {
                "schema": SCHEMA,
                "action": "would-migrate-to-current",
                "metadataDb": str(db_path),
                "schemaId": schema_id,
                "fromSchemaVersion": before_version,
                "toSchemaVersion": current_version,
                "steps": steps,
            }
        before_version = schema_marker(db_path, schema_id)

    if before_version in (V16_SCHEMA_VERSION, V17_SCHEMA_VERSION):
        result = migrate_v16_to_v17(
            db_path=db_path,
            rust_repo=rust_repo,
            backup_dir=backup_dir,
            dry_run=dry_run,
        )
        steps.append(result)
    else:
        raise RuntimeError(
            f"metadata DB schemaVersion={before_version} cannot be migrated to current {current_version}"
        )

    before_version = (
        schema_marker(db_path, schema_id) if not dry_run else V17_SCHEMA_VERSION
    )
    if before_version == V17_SCHEMA_VERSION and current_version > V17_SCHEMA_VERSION:
        if dry_run:
            steps.append(
                {
                    "schema": SCHEMA,
                    "action": "would-finalize-v17-to-current",
                    "metadataDb": str(db_path),
                    "schemaId": schema_id,
                    "fromSchemaVersion": V17_SCHEMA_VERSION,
                    "toSchemaVersion": current_version,
                }
            )
        else:
            backup_path = backup_database(db_path, backup_dir, "v17-to-current")
            with sqlite3.connect(db_path) as conn:
                conn.execute("PRAGMA foreign_keys = ON")
                conn.executescript(current_imported_known_files_sql(rust_repo))
                conn.execute(
                    "UPDATE metadata_schema SET schema_version = ? WHERE schema_id = ?",
                    (current_version, schema_id),
                )
                conn.commit()
            steps.append(
                {
                    "schema": SCHEMA,
                    "action": "finalized-v17-to-current",
                    "metadataDb": str(db_path),
                    "backup": str(backup_path),
                    "schemaId": schema_id,
                    "fromSchemaVersion": V17_SCHEMA_VERSION,
                    "toSchemaVersion": current_version,
                }
            )

    final_version = (
        schema_marker(db_path, schema_id) if not dry_run else current_version
    )
    if any(str(step.get("action", "")).startswith("would-") for step in steps):
        action = "would-migrate-to-current"
    elif all(
        step.get("action") in ("noop-current", "noop-v17-shape-current")
        for step in steps
    ):
        action = "noop-current"
    else:
        action = "migrated-to-current"
    return {
        "schema": SCHEMA,
        "action": action,
        "metadataDb": str(db_path),
        "schemaId": schema_id,
        "fromSchemaVersion": original_version,
        "toSchemaVersion": final_version,
        "steps": steps,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata-db", type=Path, default=default_metadata_db())
    parser.add_argument("--rust-repo", type=Path, default=default_rust_repo())
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = migrate_to_current(
        db_path=args.metadata_db,
        rust_repo=args.rust_repo,
        backup_dir=args.backup_dir,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
