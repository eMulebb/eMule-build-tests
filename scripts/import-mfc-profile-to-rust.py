"""Create a fresh eMuleBB Rust profile from a stock eMule config directory."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from emule_test_harness import mfc_known_met, mfc_profile_import  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-repo", type=Path, required=True)
    parser.add_argument("--emule-config-dir", type=Path, required=True)
    parser.add_argument("--rust-profile-dir", type=Path, required=True)
    parser.add_argument("--kad-bootstrap-limit", type=int, default=40)
    parser.add_argument("--import-user-hash", action="store_true")
    parser.add_argument(
        "--scan-shared-roots",
        action="store_true",
        help="Fallback to walking shared roots when sharedcache.dat has no matching path data.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    summary = mfc_profile_import.import_stock_mfc_profile(
        rust_repo=args.rust_repo,
        emule_config_dir=args.emule_config_dir,
        rust_profile_dir=args.rust_profile_dir,
        kad_bootstrap_limit=args.kad_bootstrap_limit,
        import_user_hash=args.import_user_hash,
        scan_shared_roots=args.scan_shared_roots,
        dry_run=args.dry_run,
    )
    print(mfc_known_met.summary_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
