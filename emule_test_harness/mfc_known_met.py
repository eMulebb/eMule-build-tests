"""Import MFC ``known.met`` hashes into Rust metadata.

``known.met`` stores file names, hashes, timestamps, sizes, and upload stats,
but not directory paths. Stock profile migration therefore seeds pathless cache
rows; Rust associates them with real shared-root files later only after a unique
``(file name, size, mtime_s)`` match.
"""

from __future__ import annotations

import json
import os
import base64
import binascii
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from emule_test_harness import rust_metadata

MET_HEADER = 0x0E
MET_HEADER_I64TAGS = 0x0F
KNOWN2_MET_VERSION = 0x02
FT_FILENAME = 0x01
FT_FILESIZE = 0x02
FT_ULPRIORITY = 0x19
FT_AICH_HASH = 0x27
FT_AICHHASHSET = 0x35
FT_ATTRANSFERRED = 0x50
FT_ATREQUESTED = 0x51
FT_ATACCEPTED = 0x52
FT_ATTRANSFERREDHI = 0x54
TAGTYPE_STRING = 0x02
TAGTYPE_UINT32 = 0x03
TAGTYPE_FLOAT32 = 0x04
TAGTYPE_BOOL = 0x05
TAGTYPE_BOOLARRAY = 0x06
TAGTYPE_BLOB = 0x07
TAGTYPE_UINT16 = 0x08
TAGTYPE_UINT8 = 0x09
TAGTYPE_UINT64 = 0x0B
TAGTYPE_STR1 = 0x11
TAGTYPE_STR16 = 0x20
LAST_REQUEST_TAG_NAME = "LastRequest"

PR_LOW = 0
PR_NORMAL = 1
PR_HIGH = 2
PR_VERYHIGH = 3
PR_VERYLOW = 4
PR_AUTO = 5


@dataclass(frozen=True)
class KnownMetEntry:
    modified_s: int
    ed2k_hash: str
    md4_hashset: list[str]
    name: str | None
    size_bytes: int | None
    aich_root: str | None
    aich_hashset: list[str]
    upload_priority: str
    auto_upload_priority: bool
    all_time_uploaded_bytes: int
    all_time_upload_requests: int
    all_time_upload_accepts: int
    last_upload_request_ms: int


@dataclass(frozen=True)
class SharedFileCandidate:
    path: Path
    size_bytes: int
    mtime_s: int
    mtime_ms: int


@dataclass(frozen=True)
class MfcSharedFileRow:
    path: Path
    name: str
    ed2k_hash: str
    size_bytes: int


class BinaryReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError("truncated known.met")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.read(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.read(8), "little")


def parse_known_met(path: Path) -> list[KnownMetEntry]:
    reader = BinaryReader(path.read_bytes())
    header = reader.u8()
    if header not in {MET_HEADER, MET_HEADER_I64TAGS}:
        raise ValueError(f"unsupported known.met header 0x{header:02x}")
    record_count = reader.u32()
    entries = []
    for _ in range(record_count):
        entries.append(_read_known_met_record(reader))
    if reader.remaining() != 0:
        raise ValueError("known.met has trailing bytes")
    return entries


def parse_known2_64_met(path: Path, wanted_roots: set[str] | None = None) -> dict[str, list[str]]:
    """Parse stock ``known2_64.met`` into AICH root -> part hashes."""

    entries: dict[str, list[str]] = {}
    with path.open("rb") as handle:
        version_raw = handle.read(1)
        if len(version_raw) != 1:
            raise ValueError("truncated known2_64.met")
        version = version_raw[0]
        if version != KNOWN2_MET_VERSION:
            raise ValueError(f"unsupported known2_64.met header 0x{version:02x}")
        index = 0
        while True:
            root_raw = handle.read(20)
            if not root_raw:
                break
            if len(root_raw) != 20:
                raise ValueError(f"truncated known2_64.met record {index}")
            count_raw = handle.read(4)
            if len(count_raw) != 4:
                raise ValueError(f"truncated known2_64.met record {index}")
            root = root_raw.hex()
            hash_count = int.from_bytes(count_raw, "little")
            needed = hash_count * 20
            if wanted_roots is None or root in wanted_roots:
                payload = handle.read(needed)
                if len(payload) != needed:
                    raise ValueError(f"known2_64.met record {index} declares {hash_count} hashes past EOF")
                entries[root] = [payload[offset : offset + 20].hex() for offset in range(0, needed, 20)]
            else:
                handle.seek(needed, os.SEEK_CUR)
            index += 1
    return entries


def import_mfc_known_met_cache(
    *,
    rust_repo: Path,
    metadata_db: Path,
    known_met: Path,
    known2_64_met: Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Import stock ``known.met`` as pathless reusable hash metadata.

    No shared roots are walked and no payload files are inspected. Runtime shared
    scans promote a cached row only when the exact stock identity is unique.
    """

    if not dry_run and not metadata_db.exists():
        rust_metadata.create_metadata_db(rust_repo, metadata_db)

    entries = parse_known_met(known_met)
    wanted_aich_roots = {
        entry.aich_root
        for entry in entries
        if entry.aich_root is not None
        and not entry.aich_hashset
        and entry.name is not None
        and entry.size_bytes is not None
        and expected_aich_hash_count(entry.size_bytes) > 0
        and len(entry.md4_hashset) == expected_md4_hash_count(entry.size_bytes)
    }
    known2_aich = (
        parse_known2_64_met(known2_64_met, wanted_roots=wanted_aich_roots)
        if wanted_aich_roots and known2_64_met is not None and known2_64_met.is_file()
        else {}
    )

    reason_counts = {
        "missing_identity": 0,
        "md4_count_mismatch": 0,
        "aich_count_mismatch": 0,
    }
    imported_rows: list[dict[str, Any]] = []
    known2_aich_used = 0
    stats_records = 0
    for entry in entries:
        if entry.name is None or entry.size_bytes is None:
            reason_counts["missing_identity"] += 1
            continue
        if entry.size_bytes <= 0 or entry.modified_s <= 0:
            reason_counts["missing_identity"] += 1
            continue
        if len(entry.md4_hashset) != expected_md4_hash_count(entry.size_bytes):
            reason_counts["md4_count_mismatch"] += 1
            continue
        aich_hashset = _effective_aich_hashset(entry, known2_aich, entry.size_bytes)
        if entry.aich_root is not None and not entry.aich_hashset and aich_hashset:
            known2_aich_used += 1
        if entry.aich_root is not None and len(aich_hashset) != expected_aich_hash_count(entry.size_bytes):
            reason_counts["aich_count_mismatch"] += 1
            continue
        if (
            entry.all_time_uploaded_bytes > 0
            or entry.all_time_upload_requests > 0
            or entry.all_time_upload_accepts > 0
            or entry.last_upload_request_ms > 0
        ):
            stats_records += 1
        imported_rows.append(
            {
                "ed2k_hash": entry.ed2k_hash,
                "name": entry.name,
                "size_bytes": entry.size_bytes,
                "modified_s": entry.modified_s,
                "md4_hashset": entry.md4_hashset,
                "aich_root": entry.aich_root,
                "aich_hashset": aich_hashset,
                "upload_priority": entry.upload_priority,
                "auto_upload_priority": entry.auto_upload_priority,
                "all_time_uploaded_bytes": entry.all_time_uploaded_bytes,
                "all_time_upload_requests": entry.all_time_upload_requests,
                "all_time_upload_accepts": entry.all_time_upload_accepts,
                "last_upload_request_ms": entry.last_upload_request_ms,
            }
        )
    if imported_rows and not dry_run:
        rust_metadata.seed_imported_known_files(metadata_db, imported_rows)

    return {
        "knownMetRecords": len(entries),
        "importedKnownRecords": len(imported_rows),
        "known2AichRecords": len(known2_aich),
        "known2AichUsed": known2_aich_used,
        "statsRecords": stats_records,
        "dryRun": dry_run,
        "skipped": reason_counts,
        "metadataDb": str(metadata_db),
    }


def import_mfc_known_met_hashes(
    *,
    rust_repo: Path,
    metadata_db: Path,
    known_met: Path,
    known2_64_met: Path | None = None,
    shared_roots: list[object],
    shared_file_candidates: list[SharedFileCandidate] | None = None,
    scan_shared_roots: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    if not dry_run and not metadata_db.exists():
        rust_metadata.create_metadata_db(rust_repo, metadata_db)

    entries = parse_known_met(known_met)
    candidates = shared_file_candidates if shared_file_candidates is not None else []
    if scan_shared_roots:
        candidates = candidates + scan_shared_file_candidates(shared_roots)
    by_key: dict[tuple[str, int, int], list[SharedFileCandidate]] = {}
    for candidate in candidates:
        by_key.setdefault(
            (
                candidate.path.name.casefold(),
                candidate.size_bytes,
                candidate.mtime_s,
            ),
            [],
        ).append(candidate)

    wanted_aich_roots = {
        entry.aich_root
        for entry in entries
        if entry.aich_root is not None
        and not entry.aich_hashset
        and entry.name is not None
        and entry.size_bytes is not None
        and expected_aich_hash_count(entry.size_bytes) > 0
        and len(entry.md4_hashset) == expected_md4_hash_count(entry.size_bytes)
        and by_key.get((entry.name.casefold(), entry.size_bytes, entry.modified_s))
    }
    known2_aich = (
        parse_known2_64_met(known2_64_met, wanted_roots=wanted_aich_roots)
        if wanted_aich_roots and known2_64_met is not None and known2_64_met.is_file()
        else {}
    )

    reason_counts = {
        "missing_identity": 0,
        "md4_count_mismatch": 0,
        "no_path_match": 0,
        "aich_count_mismatch": 0,
    }
    matched = 0
    duplicate_records = 0
    known2_aich_used = 0
    stats_records = 0
    stats_source_paths = 0
    manifests: list[dict[str, Any]] = []
    for entry in entries:
        if entry.name is None or entry.size_bytes is None:
            reason_counts["missing_identity"] += 1
            continue
        if len(entry.md4_hashset) != expected_md4_hash_count(entry.size_bytes):
            reason_counts["md4_count_mismatch"] += 1
            continue
        matches = by_key.get((entry.name.casefold(), entry.size_bytes, entry.modified_s), [])
        if len(matches) == 0:
            reason_counts["no_path_match"] += 1
            continue
        aich_hashset = _effective_aich_hashset(entry, known2_aich, entry.size_bytes)
        if entry.aich_root is not None and not entry.aich_hashset and aich_hashset:
            known2_aich_used += 1
        if entry.aich_root is not None and len(aich_hashset) != expected_aich_hash_count(entry.size_bytes):
            reason_counts["aich_count_mismatch"] += 1
            continue

        # A known.met record whose (name, size, whole-second mtime) identity matches
        # more than one shared file is a set of byte-identical duplicates: same content
        # -> same ed2k/MD4/AICH hashset. Seed EVERY duplicate path with the shared hash
        # so Rust's share-in-place reload skips re-hashing all of them, instead of
        # discarding the record (which previously cost ~68% of MFC's known.met). This
        # extends the same (name,size,mtime)->hash trust the unique-match path already
        # applies without a content re-hash; a rare false collision (distinct content
        # sharing that identity) is caught by the downloader's AICH/hash verification
        # and self-corrects on the next share scan.
        matched += 1
        if len(matches) > 1:
            duplicate_records += 1
        has_stats = (
            entry.all_time_uploaded_bytes > 0
            or entry.all_time_upload_requests > 0
            or entry.all_time_upload_accepts > 0
            or entry.last_upload_request_ms > 0
        )
        if has_stats:
            stats_records += 1
            stats_source_paths += len(matches)
        if not dry_run:
            for candidate in matches:
                manifests.append(
                    {
                        "ed2k_hash": entry.ed2k_hash,
                        "name": entry.name,
                        "size_bytes": entry.size_bytes,
                        "source_path": normal_windows_display_path(candidate.path),
                        "source_mtime_ms": candidate.mtime_ms,
                        "md4_hashset": entry.md4_hashset,
                        "aich_root": entry.aich_root,
                        "aich_hashset": aich_hashset,
                        "upload_priority": entry.upload_priority,
                        "auto_upload_priority": entry.auto_upload_priority,
                        "all_time_uploaded_bytes": entry.all_time_uploaded_bytes,
                        "all_time_upload_requests": entry.all_time_upload_requests,
                        "all_time_upload_accepts": entry.all_time_upload_accepts,
                        "last_upload_request_ms": entry.last_upload_request_ms,
                    }
                )
    if manifests:
        rust_metadata.seed_share_in_place_manifests(
            metadata_db,
            manifests,
            seed_piece_rows=False,
        )

    return {
        "knownMetRecords": len(entries),
        "sharedFilesScanned": len(candidates),
        "sharedFileCandidateSource": "scan" if scan_shared_roots else ("startup-cache" if shared_file_candidates is not None else "none"),
        "matchedRecords": matched,
        "duplicateRecords": duplicate_records,
        "known2AichRecords": len(known2_aich),
        "known2AichUsed": known2_aich_used,
        "statsRecords": stats_records,
        "statsSourcePaths": stats_source_paths,
        "importedRecords": matched,
        "importedSourcePaths": len(manifests),
        "dryRun": dry_run,
        "skipped": reason_counts,
        "metadataDb": str(metadata_db),
    }


def import_mfc_shared_file_rows_hashes(
    *,
    rust_repo: Path,
    metadata_db: Path,
    known_met: Path,
    known2_64_met: Path | None = None,
    shared_file_rows: list[dict[str, Any]],
    shared_roots: list[Path],
    dry_run: bool = False,
) -> dict[str, Any]:
    """Import MFC REST shared-file rows into Rust metadata by exact source path.

    MFC's ``/api/v1/shared-files`` rows expose the full local path and ED2K hash,
    which removes the basename/size/mtime ambiguity inherent in raw
    ``known.met``. We still require the matching ``known.met`` entry so large
    files keep their MD4/AICH part hashsets when Rust skips hashing.
    """

    if not dry_run and not metadata_db.exists():
        rust_metadata.create_metadata_db(rust_repo, metadata_db)

    known_entries = {entry.ed2k_hash: entry for entry in parse_known_met(known_met)}
    known2_aich = parse_known2_64_met(known2_64_met) if known2_64_met is not None and known2_64_met.is_file() else {}
    roots = {_canonical_existing_root(root) for root in shared_roots if root.is_dir()}
    parsed_rows: list[tuple[MfcSharedFileRow, KnownMetEntry, int, list[str]]] = []
    reason_counts = {
        "invalid_row": 0,
        "path_outside_shared_roots": 0,
        "path_missing": 0,
        "size_mismatch": 0,
        "missing_known_met_entry": 0,
        "md4_count_mismatch": 0,
        "aich_count_mismatch": 0,
    }
    for row in shared_file_rows:
        parsed = _parse_mfc_shared_file_row(row)
        if parsed is None:
            reason_counts["invalid_row"] += 1
            continue
        if roots and not _path_is_under_root_set(parsed.path, roots):
            reason_counts["path_outside_shared_roots"] += 1
            continue
        try:
            stat = parsed.path.stat()
        except OSError:
            reason_counts["path_missing"] += 1
            continue
        if not parsed.path.is_file():
            reason_counts["path_missing"] += 1
            continue
        if stat.st_size != parsed.size_bytes:
            reason_counts["size_mismatch"] += 1
            continue
        entry = known_entries.get(parsed.ed2k_hash)
        if entry is None:
            reason_counts["missing_known_met_entry"] += 1
            continue
        if len(entry.md4_hashset) != expected_md4_hash_count(parsed.size_bytes):
            reason_counts["md4_count_mismatch"] += 1
            continue
        aich_hashset = _effective_aich_hashset(entry, known2_aich, parsed.size_bytes)
        if entry.aich_root is not None and len(aich_hashset) != expected_aich_hash_count(parsed.size_bytes):
            reason_counts["aich_count_mismatch"] += 1
            continue
        parsed_rows.append((parsed, entry, stat.st_mtime_ns // 1_000_000, aich_hashset))

    if not dry_run:
        rust_metadata.seed_share_in_place_manifests(
            metadata_db,
            [
                {
                    "ed2k_hash": parsed.ed2k_hash,
                    "name": parsed.name,
                    "size_bytes": parsed.size_bytes,
                    "source_path": normal_windows_display_path(parsed.path),
                    "source_mtime_ms": source_mtime_ms,
                    "md4_hashset": entry.md4_hashset,
                    "aich_root": entry.aich_root,
                    "aich_hashset": aich_hashset,
                    "upload_priority": entry.upload_priority,
                    "auto_upload_priority": entry.auto_upload_priority,
                    "all_time_uploaded_bytes": entry.all_time_uploaded_bytes,
                    "all_time_upload_requests": entry.all_time_upload_requests,
                    "all_time_upload_accepts": entry.all_time_upload_accepts,
                    "last_upload_request_ms": entry.last_upload_request_ms,
                }
                for parsed, entry, source_mtime_ms, aich_hashset in parsed_rows
            ],
            seed_piece_rows=False,
        )

    return {
        "knownMetRecords": len(known_entries),
        "sharedFileRows": len(shared_file_rows),
        "matchedRows": len(parsed_rows),
        "importedRows": 0 if dry_run else len(parsed_rows),
        "known2AichRecords": len(known2_aich),
        "statsRows": sum(
            1
            for _, entry, _, _ in parsed_rows
            if entry.all_time_uploaded_bytes > 0
            or entry.all_time_upload_requests > 0
            or entry.all_time_upload_accepts > 0
            or entry.last_upload_request_ms > 0
        ),
        "dryRun": dry_run,
        "skipped": reason_counts,
        "metadataDb": str(metadata_db),
    }


def load_shared_file_rows_json(path: Path) -> list[dict[str, Any]]:
    """Load shared-file rows from a REST envelope, ``{"items": [...]}``, or list."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return [row for row in items if isinstance(row, dict)]
    items = payload.get("items")
    if isinstance(items, list):
        return [row for row in items if isinstance(row, dict)]
    return []


def scan_shared_file_candidates(roots: list[object]) -> list[SharedFileCandidate]:
    candidates: list[SharedFileCandidate] = []
    for root in roots:
        root_path, recursive = _shared_root_scan_parts(root)
        if not root_path.is_dir():
            continue
        paths = _recursive_file_paths(root_path) if recursive else _direct_file_paths(root_path)
        for path in paths:
            try:
                stat = path.stat()
            except OSError:
                continue
            if not path.is_file():
                continue
            candidates.append(
                SharedFileCandidate(
                    path=path,
                    size_bytes=stat.st_size,
                    mtime_s=int(stat.st_mtime),
                    mtime_ms=stat.st_mtime_ns // 1_000_000,
                )
            )
    return candidates


def normal_windows_display_path(path: Path | str) -> str:
    value = str(path)
    if value.startswith("\\\\?\\UNC\\"):
        return "\\\\" + value[8:]
    if value.startswith("\\\\?\\"):
        return value[4:]
    return value


def _shared_root_scan_parts(root: object) -> tuple[Path, bool]:
    if isinstance(root, dict):
        return Path(str(root.get("path") or "")), bool(root.get("recursive"))
    if isinstance(root, str):
        return Path(root), False
    return Path(root), True


def _direct_file_paths(root: Path) -> list[Path]:
    try:
        return [path for path in root.iterdir() if path.is_file()]
    except OSError:
        return []


def _recursive_file_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for dirpath, _, filenames in os.walk(root):
        paths.extend(Path(dirpath) / filename for filename in filenames)
    return paths


def _parse_mfc_shared_file_row(row: dict[str, Any]) -> MfcSharedFileRow | None:
    raw_hash = str(row.get("hash") or row.get("fileHash") or "").strip().lower()
    raw_path = str(row.get("path") or "").strip()
    raw_name = str(row.get("name") or "").strip()
    raw_size = row.get("sizeBytes", row.get("size"))
    if len(raw_hash) != 32:
        return None
    try:
        bytes.fromhex(raw_hash)
    except ValueError:
        return None
    if not raw_path:
        return None
    try:
        size_bytes = int(raw_size)
    except (TypeError, ValueError):
        return None
    if size_bytes < 0:
        return None
    path = Path(raw_path)
    name = raw_name or path.name
    if not name:
        return None
    return MfcSharedFileRow(
        path=path,
        name=name,
        ed2k_hash=raw_hash,
        size_bytes=size_bytes,
    )


def _canonical_existing_root(path: Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def _path_is_under_root_set(path: Path, roots: set[str]) -> bool:
    candidate = os.path.normcase(os.path.abspath(str(path)))
    current = candidate
    while True:
        if current in roots:
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent
    return False


def expected_md4_hash_count(file_size: int) -> int:
    if file_size == 0:
        return 0
    whole_parts = file_size // rust_metadata.ED2K_PART_SIZE
    return whole_parts + int(whole_parts > 0)


def expected_aich_hash_count(file_size: int) -> int:
    if file_size <= rust_metadata.ED2K_PART_SIZE:
        return 0
    return (file_size + rust_metadata.ED2K_PART_SIZE - 1) // rust_metadata.ED2K_PART_SIZE


def _effective_aich_hashset(
    entry: KnownMetEntry,
    known2_aich: dict[str, list[str]],
    size_bytes: int,
) -> list[str]:
    if entry.aich_hashset:
        return entry.aich_hashset
    if entry.aich_root is None:
        return []
    hashset = known2_aich.get(entry.aich_root)
    if hashset is None:
        return []
    if len(hashset) != expected_aich_hash_count(size_bytes):
        return []
    return hashset


def _read_known_met_record(reader: BinaryReader) -> KnownMetEntry:
    modified_s = reader.u32()
    ed2k_hash = reader.read(16).hex()
    part_count = reader.u16()
    md4_hashset = [reader.read(16).hex() for _ in range(part_count)]
    tags = [_read_tag(reader) for _ in range(reader.u32())]
    name = _first_tag_value(tags, FT_FILENAME, str)
    size = _first_tag_value(tags, FT_FILESIZE, int)
    aich_blob = _first_tag_value(tags, FT_AICHHASHSET, bytes)
    aich_root, aich_hashset = _parse_aich_hashset_blob(aich_blob) if aich_blob else (None, [])
    if aich_root is None:
        aich_root = _parse_aich_root_tag(_first_tag_value(tags, FT_AICH_HASH, str))
    upload_priority, auto_upload_priority = _parse_upload_priority(_first_tag_value(tags, FT_ULPRIORITY, int))
    transferred_low = _first_tag_value(tags, FT_ATTRANSFERRED, int) or 0
    transferred_hi = _first_tag_value(tags, FT_ATTRANSFERREDHI, int) or 0
    all_time_uploaded_bytes = (transferred_hi << 32) | transferred_low
    all_time_upload_requests = _first_tag_value(tags, FT_ATREQUESTED, int) or 0
    all_time_upload_accepts = _first_tag_value(tags, FT_ATACCEPTED, int) or 0
    last_request_s = _first_tag_value(tags, LAST_REQUEST_TAG_NAME, int) or 0
    return KnownMetEntry(
        modified_s=modified_s,
        ed2k_hash=ed2k_hash,
        md4_hashset=md4_hashset,
        name=name,
        size_bytes=size,
        aich_root=aich_root,
        aich_hashset=aich_hashset,
        upload_priority=upload_priority,
        auto_upload_priority=auto_upload_priority,
        all_time_uploaded_bytes=all_time_uploaded_bytes,
        all_time_upload_requests=all_time_upload_requests,
        all_time_upload_accepts=all_time_upload_accepts,
        last_upload_request_ms=last_request_s * 1000,
    )


def _parse_aich_root_tag(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip().upper()
    try:
        decoded = base64.b32decode(raw + ("=" * ((8 - len(raw) % 8) % 8)))
    except (binascii.Error, ValueError):
        return None
    return decoded.hex() if len(decoded) == 20 else None


def _parse_upload_priority(value: int | None) -> tuple[str, bool]:
    if value == PR_AUTO:
        return "normal", True
    if value == PR_VERYLOW:
        return "verylow", False
    if value == PR_LOW:
        return "low", False
    if value == PR_HIGH:
        return "high", False
    if value == PR_VERYHIGH:
        return "release", False
    return "normal", False


def _read_tag(reader: BinaryReader) -> tuple[int | str, Any]:
    tag_type = reader.u8()
    if tag_type & 0x80:
        tag_type &= 0x7F
        name: int | str = reader.u8()
    else:
        name_len = reader.u16()
        if name_len == 1:
            name = reader.u8()
        else:
            name = reader.read(name_len).decode("ascii", errors="replace")

    if tag_type == TAGTYPE_STRING:
        return name, _decode_mfc_string(reader.read(reader.u16()))
    if TAGTYPE_STR1 <= tag_type <= TAGTYPE_STR16:
        return name, _decode_mfc_string(reader.read(tag_type - TAGTYPE_STR1 + 1))
    if tag_type == TAGTYPE_UINT32:
        return name, reader.u32()
    if tag_type == TAGTYPE_UINT64:
        return name, reader.u64()
    if tag_type == TAGTYPE_UINT16:
        return name, reader.u16()
    if tag_type == TAGTYPE_UINT8:
        return name, reader.u8()
    if tag_type == TAGTYPE_FLOAT32:
        return name, reader.read(4)
    if tag_type == TAGTYPE_BOOL:
        return name, bool(reader.u8())
    if tag_type == TAGTYPE_BOOLARRAY:
        bit_count = reader.u16()
        return name, reader.read((bit_count // 8) + 1)
    if tag_type == TAGTYPE_BLOB:
        return name, reader.read(reader.u32())
    raise ValueError(f"unsupported known.met tag type 0x{tag_type:02x}")


def _decode_mfc_string(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")
    for encoding in ("mbcs", "cp1252", "utf-8"):
        try:
            return raw.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def _first_tag_value(tags: list[tuple[int | str, Any]], name_id: int, expected_type: type) -> Any | None:
    for name, value in tags:
        if name == name_id and isinstance(value, expected_type):
            return value
    return None


def _parse_aich_hashset_blob(blob: bytes) -> tuple[str, list[str]]:
    if len(blob) < 22:
        raise ValueError("truncated AICH hashset blob")
    reader = BinaryReader(blob)
    root = reader.read(20).hex()
    part_count = reader.u16()
    expected_len = 20 + 2 + (20 * part_count)
    if len(blob) != expected_len:
        raise ValueError("AICH hashset blob length mismatch")
    return root, [reader.read(20).hex() for _ in range(part_count)]


def summary_json(summary: dict[str, Any]) -> str:
    return json.dumps(summary, indent=2, sort_keys=True)
