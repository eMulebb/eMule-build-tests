"""Import MFC known.met hashes into an eMuleBB Rust profile metadata DB."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import mfc_known_met, soak_launch  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-repo", type=Path, required=True)
    parser.add_argument("--metadata-db", type=Path, required=True)
    parser.add_argument("--known-met", type=Path, required=True)
    parser.add_argument("--known2-64-met", type=Path)
    parser.add_argument("--inputs", type=Path, help="live-wire inputs JSON with shared_directories intent")
    parser.add_argument("--shared-root", type=Path, action="append", default=[])
    parser.add_argument("--shared-dir-file", type=Path)
    parser.add_argument("--incoming-dir", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    shared_roots: list[object] = list(args.shared_root)
    if args.inputs is not None:
        shared_roots.extend(soak_launch.load_live_wire_shared_root_entries(args.inputs))
    if args.shared_dir_file is not None:
        extra_roots = [args.incoming_dir] if args.incoming_dir is not None else None
        shared_roots.extend(soak_launch.load_shareddir_root_entries(args.shared_dir_file, extra_roots=extra_roots))
    if not shared_roots:
        parser.error("provide --inputs, --shared-root, or --shared-dir-file")

    summary = mfc_known_met.import_mfc_known_met_hashes(
        rust_repo=args.rust_repo,
        metadata_db=args.metadata_db,
        known_met=args.known_met,
        known2_64_met=args.known2_64_met,
        shared_roots=shared_roots,
        dry_run=args.dry_run,
    )
    print(mfc_known_met.summary_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
