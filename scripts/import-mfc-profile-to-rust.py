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
        "--rest-addr",
        default=mfc_profile_import.DEFAULT_REST_ADDR,
        help="Rust REST bind address. Defaults to inherited X_LOCAL_IP; loopback is not a live profile default.",
    )
    parser.add_argument("--rest-port", type=int, default=mfc_profile_import.DEFAULT_REST_PORT)
    parser.add_argument("--api-key", default=mfc_profile_import.DEFAULT_API_KEY)
    parser.add_argument(
        "--p2p-bind-ip",
        help="Rust daemon P2P bind IP override. Normally leave unset and bind P2P through --p2p-bind-interface.",
    )
    parser.add_argument(
        "--p2p-bind-interface",
        default=mfc_profile_import.DEFAULT_P2P_BIND_INTERFACE,
        help="Rust daemon P2P bind interface. Defaults to hide.me.",
    )
    parser.add_argument("--ed2k-port", type=int, default=mfc_profile_import.DEFAULT_ED2K_PORT)
    parser.add_argument("--kad-port", type=int, default=mfc_profile_import.DEFAULT_KAD_PORT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    summary = mfc_profile_import.import_stock_mfc_profile(
        rust_repo=args.rust_repo,
        emule_config_dir=args.emule_config_dir,
        rust_profile_dir=args.rust_profile_dir,
        kad_bootstrap_limit=args.kad_bootstrap_limit,
        import_user_hash=args.import_user_hash,
        rest_addr=args.rest_addr,
        rest_port=args.rest_port,
        api_key=args.api_key,
        p2p_bind_ip=args.p2p_bind_ip,
        p2p_bind_interface=args.p2p_bind_interface,
        ed2k_port=args.ed2k_port,
        kad_port=args.kad_port,
        dry_run=args.dry_run,
    )
    print(mfc_known_met.summary_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
