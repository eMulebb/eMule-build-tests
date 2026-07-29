from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import time
from pathlib import Path
from types import ModuleType
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RUST_SOAK_CONTROL = REPO_ROOT / "scripts" / "rust-soak-control.py"


def _load_rust_soak_control() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rust_soak_control_script", RUST_SOAK_CONTROL)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shared_directory_summary_redacts_paths_and_keeps_flags() -> None:
    control = _load_rust_soak_control()

    summary = control.summarize_shared_directory_rows(
        [
            {
                "path": r"F:\Private\Library\\",
                "accessible": True,
                "shareable": True,
                "recursive": True,
                "monitorOwned": False,
            },
            {
                "path": r"F:\Private\Library",
                "accessible": True,
                "shareable": True,
                "recursive": False,
                "monitorOwned": True,
            },
        ]
    )

    assert summary["count"] == 2
    assert summary["duplicateCount"] == 1
    assert summary["counts"]["accessible"] == 2
    assert summary["counts"]["recursive"] == 1
    assert summary["counts"]["monitorOwned"] == 1
    assert "Private" not in repr(summary)
    assert "Library" not in repr(summary)


def test_shared_summary_compare_reports_root_and_count_delta() -> None:
    control = _load_rust_soak_control()

    shared = control.private_path_fingerprint(r"F:\Private\Library")
    rust_only = control.private_path_fingerprint(r"F:\Private\RustOnly")
    mfc_only = control.private_path_fingerprint(r"F:\Private\MfcOnly")
    comparison = control.compare_shared_summaries(
        {
            "sharedFilesTotal": 10,
            "roots": {"fingerprints": [shared, rust_only]},
        },
        {
            "sharedFilesTotal": 12,
            "roots": {"fingerprints": [shared, mfc_only]},
        },
    )

    assert comparison == {
        "enabled": True,
        "rootFingerprintsMatch": False,
        "rustOnlyRootFingerprintCount": 1,
        "mfcOnlyRootFingerprintCount": 1,
        "rustOnlyRootFingerprints": [rust_only],
        "mfcOnlyRootFingerprints": [mfc_only],
        "sharedFilesDeltaRustMinusMfc": -2,
    }


def test_shared_summary_compare_disables_for_unavailable_mfc() -> None:
    control = _load_rust_soak_control()

    comparison = control.compare_shared_summaries(
        {"sharedFilesTotal": 10, "roots": {"fingerprints": ["same"]}},
        {"label": "mfc", "available": False, "error": "TimeoutError"},
    )

    assert comparison == {"enabled": False, "reason": "mfc-unavailable"}


def test_shared_summary_tolerates_optional_mfc_timeout(monkeypatch) -> None:
    control = _load_rust_soak_control()

    def fake_summarize(base_url: str, api_key: str, label: str, **kwargs) -> dict[str, object]:
        del api_key, kwargs
        if label == "mfc":
            raise TimeoutError(r"timed out at http://private.example/F:\Private\Library")
        return {
            "label": label,
            "baseUrl": base_url,
            "sharedFilesTotal": 10,
            "roots": {"fingerprints": ["root-a"]},
            "items": {"fingerprints": ["root-a"]},
            "rootFingerprints": ["root-a"],
            "itemFingerprints": ["root-a"],
            "rootsMissingFromItems": [],
            "itemsMissingFromRoots": [],
        }

    monkeypatch.setattr(control, "summarize_shared_directories", fake_summarize)

    result = control.shared_summary(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="rust",
            mfc_base_url="http://private.example:4732/api/v1",
            mfc_api_key="mfc",
            include_fingerprints=False,
            fingerprint_sample_limit=20,
            compare_shared_file_hashes=False,
            compare_shared_file_paths=False,
            compare_shared_file_roots=False,
            include_root_groups=False,
            shared_file_page_size=1000,
            shared_file_timeout_seconds=120.0,
            shared_file_sleep_seconds=0.05,
        )
    )

    assert result["rust"]["sharedFilesTotal"] == 10
    assert result["mfc"] == {"label": "mfc", "available": False, "error": "TimeoutError"}
    assert result["comparison"] == {"enabled": False, "reason": "mfc-unavailable"}
    assert "private.example" not in repr(result)
    assert "Private" not in repr(result)


def test_shared_summary_requires_mfc_for_deep_compare_after_timeout(monkeypatch) -> None:
    control = _load_rust_soak_control()

    def fake_summarize(base_url: str, api_key: str, label: str, **kwargs) -> dict[str, object]:
        del base_url, api_key, kwargs
        if label == "mfc":
            raise TimeoutError("timed out")
        return {
            "label": label,
            "sharedFilesTotal": 10,
            "roots": {"fingerprints": ["root-a"]},
            "items": {"fingerprints": ["root-a"]},
            "rootFingerprints": ["root-a"],
            "itemFingerprints": ["root-a"],
            "rootsMissingFromItems": [],
            "itemsMissingFromRoots": [],
        }

    monkeypatch.setattr(control, "summarize_shared_directories", fake_summarize)

    with pytest.raises(RuntimeError, match="cannot compare shared-file hashes"):
        control.shared_summary(
            SimpleNamespace(
                base_url="http://192.0.2.10:4731/api/v1",
                api_key="rust",
                mfc_base_url="http://192.0.2.20:4732/api/v1",
                mfc_api_key="mfc",
                include_fingerprints=False,
                fingerprint_sample_limit=20,
                compare_shared_file_hashes=True,
                compare_shared_file_paths=False,
                compare_shared_file_roots=False,
                include_root_groups=False,
                shared_file_page_size=1000,
                shared_file_timeout_seconds=120.0,
                shared_file_sleep_seconds=0.05,
            )
        )


def test_summarize_shared_directories_reads_reload_progress_shape(monkeypatch) -> None:
    control = _load_rust_soak_control()

    def fake_request_json(_base_url: str, path: str, **_kwargs) -> dict[str, object]:
        if path == "/shared-directories":
            return {
                "hashingCount": 4,
                "roots": [{"path": r"C:\Share", "accessible": True, "shareable": True}],
                "items": [{"path": r"C:\Share", "accessible": True, "shareable": True}],
                "reloadProgress": {
                    "phase": "hashing",
                    "running": True,
                    "pending": False,
                    "plannedHashCount": 5,
                    "hashedCount": 1,
                    "failedHashCount": 0,
                    "reusedCount": 10,
                },
            }
        return {"items": [], "total": 42}

    monkeypatch.setattr(control, "request_json", fake_request_json)
    summary = control.summarize_shared_directories("http://192.0.2.10:4731/api/v1", "rust", "rust")

    assert summary["hashingCount"] == 4
    assert summary["sharedFilesTotal"] == 42
    assert summary["reload"] == {
        "phase": "hashing",
        "running": True,
        "pending": False,
        "scannedCount": None,
        "plannedHashCount": 5,
        "hashedCount": 1,
        "failedHashCount": 0,
        "reusedCount": 10,
        "skippedIntakeCount": None,
        "prunedCount": None,
        "staleHashCount": None,
    }


def test_sanitize_status_reads_shared_directory_reload_progress() -> None:
    control = _load_rust_soak_control()

    sample = control.sanitize_status(
        {
            "runtimeDiagnostics": {
                "sharedDirectoryReloadProgress": {
                    "phase": "queued",
                    "scannedCount": 100,
                    "plannedHashCount": 5,
                    "reusedCount": 95,
                }
            }
        }
    )

    assert sample["sharedReloadPhase"] == "queued"
    assert sample["sharedReloadScannedCount"] == 100
    assert sample["sharedReloadPlannedHashCount"] == 5
    assert sample["sharedReloadReusedCount"] == 95


def test_shared_library_settled_check_requires_no_hashing_or_reload() -> None:
    control = _load_rust_soak_control()

    check = control.shared_library_settled_check(
        {
            "sharedFilesTotal": 100,
            "roots": {"count": 2},
            "items": {"count": 2},
            "hashingCount": 12,
            "reload": {"running": True, "pending": False, "phase": "hashing"},
        },
        min_root_count=1,
        min_shared_files=1,
    )

    assert check["ok"] is False
    assert check["missing"] == ["hashingComplete", "reloadNotRunning"]
    assert check["rootCount"] == 2
    assert check["sharedFilesTotal"] == 100


def test_shared_library_settled_check_accepts_stable_shared_counts() -> None:
    control = _load_rust_soak_control()

    check = control.shared_library_settled_check(
        {
            "sharedFilesTotal": 100,
            "roots": {"count": 2},
            "items": {"count": 2},
            "hashingCount": 0,
            "reload": {"running": False, "pending": False, "phase": "idle", "failedHashCount": 0},
        },
        min_root_count=1,
        min_shared_files=1,
    )

    assert check["ok"] is True
    assert check["missing"] == []


def test_shared_reload_settled_proof_waits_for_consecutive_stable_samples(monkeypatch) -> None:
    control = _load_rust_soak_control()
    samples = iter(
        [
            {
                "sharedFilesTotal": 100,
                "roots": {"count": 2},
                "items": {"count": 2},
                "hashingCount": 1,
                "reload": {"running": True, "pending": False, "phase": "hashing"},
            },
            {
                "sharedFilesTotal": 100,
                "roots": {"count": 2},
                "items": {"count": 2},
                "hashingCount": 0,
                "reload": {"running": False, "pending": False, "phase": "idle"},
            },
            {
                "sharedFilesTotal": 100,
                "roots": {"count": 2},
                "items": {"count": 2},
                "hashingCount": 0,
                "reload": {"running": False, "pending": False, "phase": "idle"},
            },
        ]
    )

    monkeypatch.setattr(control, "summarize_shared_directories", lambda *args, **kwargs: next(samples))
    result = control.rust_shared_reload_settled_proof(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="rust",
            timeout_seconds=10.0,
            poll_seconds=0.0,
            request_timeout_seconds=1.0,
            stable_samples=2,
            min_root_count=1,
            min_shared_files=1,
            fingerprint_sample_limit=20,
            max_observations=20,
        )
    )

    assert result["ok"] is True
    assert result["stability"] == {"ok": True, "sampleCount": 2, "deltas": {}}
    assert result["sample"]["hashingCount"] == 0
    assert "192.0.2.10" not in repr(result)


def test_shared_reload_settled_proof_fails_while_hashing(monkeypatch) -> None:
    control = _load_rust_soak_control()

    monkeypatch.setattr(
        control,
        "summarize_shared_directories",
        lambda *args, **kwargs: {
            "sharedFilesTotal": 100,
            "roots": {"count": 2},
            "items": {"count": 2},
            "hashingCount": 12,
            "reload": {"running": True, "pending": False, "phase": "hashing"},
        },
    )
    result = control.rust_shared_reload_settled_proof(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="rust",
            timeout_seconds=0.0,
            poll_seconds=0.0,
            request_timeout_seconds=1.0,
            stable_samples=2,
            min_root_count=1,
            min_shared_files=1,
            fingerprint_sample_limit=20,
            max_observations=20,
        )
    )

    assert result["ok"] is False
    assert result["sample"]["missing"] == ["hashingComplete", "reloadNotRunning"]
    assert "192.0.2.10" not in repr(result)


def test_publish_visibility_check_requires_ed2k_and_kad_maturity() -> None:
    control = _load_rust_soak_control()

    check = control.publish_visibility_check(
        {
            "ed2kConnected": True,
            "ed2kHighId": True,
            "ed2kVisibilityPercent": 12.0,
            "ed2kPendingEntries": 44000,
            "kadConnected": True,
            "kadGateAllowed": True,
            "kadKeywordPublishedTotal": 10,
            "kadSourcePublishedTotal": 2,
        },
        min_ed2k_visibility_percent=95.0,
        max_ed2k_pending_entries=None,
        min_kad_keyword_published_total=1,
        min_kad_source_published_total=1,
    )

    assert check["ok"] is False
    assert check["missing"] == ["ed2kVisibilityMature"]
    assert check["ed2kVisibilityPercent"] == 12.0


def test_publish_visibility_check_accepts_mature_publish_counters() -> None:
    control = _load_rust_soak_control()

    check = control.publish_visibility_check(
        {
            "ed2kConnected": True,
            "ed2kHighId": True,
            "ed2kVisibilityPercent": 100.0,
            "ed2kPendingEntries": 0,
            "kadConnected": True,
            "kadGateAllowed": True,
            "kadKeywordPublishedTotal": 10,
            "kadSourcePublishedTotal": 2,
        },
        min_ed2k_visibility_percent=95.0,
        max_ed2k_pending_entries=0,
        min_kad_keyword_published_total=1,
        min_kad_source_published_total=1,
    )

    assert check["ok"] is True
    assert check["missing"] == []


def test_publish_visibility_proof_waits_for_consecutive_mature_samples(monkeypatch) -> None:
    control = _load_rust_soak_control()
    samples = iter(
        [
            {
                "servers": {"connected": True, "lowId": False},
                "kad": {"connected": True},
                "runtimeDiagnostics": {
                    "ed2kPublish": {"publishedEntries": 10, "pendingEntries": 90},
                    "kadPublish": {
                        "gateAllowed": True,
                        "keywordPublishedTotal": 4,
                        "sourcePublishedTotal": 2,
                    },
                },
            },
            {
                "servers": {"connected": True, "lowId": False},
                "kad": {"connected": True},
                "runtimeDiagnostics": {
                    "ed2kPublish": {"publishedEntries": 100, "pendingEntries": 0},
                    "kadPublish": {
                        "gateAllowed": True,
                        "keywordPublishedTotal": 4,
                        "sourcePublishedTotal": 2,
                    },
                },
            },
            {
                "servers": {"connected": True, "lowId": False},
                "kad": {"connected": True},
                "runtimeDiagnostics": {
                    "ed2kPublish": {"publishedEntries": 100, "pendingEntries": 0},
                    "kadPublish": {
                        "gateAllowed": True,
                        "keywordPublishedTotal": 4,
                        "sourcePublishedTotal": 2,
                    },
                },
            },
        ]
    )

    monkeypatch.setattr(control, "request_json", lambda *args, **kwargs: next(samples))
    result = control.rust_publish_visibility_proof(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="rust",
            timeout_seconds=10.0,
            poll_seconds=0.0,
            request_timeout_seconds=1.0,
            stable_samples=2,
            min_ed2k_visibility_percent=95.0,
            max_ed2k_pending_entries=0,
            min_kad_keyword_published_total=1,
            min_kad_source_published_total=1,
            max_observations=20,
        )
    )

    assert result["ok"] is True
    assert result["sample"]["ed2kVisibilityPercent"] == 100.0
    assert result["sample"]["kadSourcePublishedTotal"] == 2
    assert "192.0.2.10" not in repr(result)


def test_public_search_candidate_safety_rejects_unsafe_rows() -> None:
    control = _load_rust_soak_control()
    safe = {
        "hash": "0123456789abcdef0123456789abcdef",
        "name": "public-document.pdf",
        "sizeBytes": 1024,
        "fileType": "Doc",
        "sources": 2,
    }

    assert control.public_search_candidate_safety_reason(safe, min_sources=2, max_size_bytes=2048) is None
    assert control.public_search_candidate_safety_reason({**safe, "name": "setup.exe"}, min_sources=2, max_size_bytes=2048) == "unsafe-suffix"
    assert control.public_search_candidate_safety_reason({**safe, "fileType": "Pro"}, min_sources=2, max_size_bytes=2048) == "unsafe-type"
    assert control.public_search_candidate_safety_reason({**safe, "name": "linux keygen doc.pdf"}, min_sources=2, max_size_bytes=2048) == "unsafe-name-token"
    assert control.public_search_candidate_safety_reason({**safe, "hash": "ABCDEF0123456789ABCDEF0123456789"}, min_sources=2, max_size_bytes=2048) == "bad-hash"
    assert control.public_search_candidate_safety_reason({**safe, "sizeBytes": 4096}, min_sources=2, max_size_bytes=2048) == "too-large"
    assert control.public_search_candidate_safety_reason({**safe, "sources": 1}, min_sources=2, max_size_bytes=2048) == "weak-sources"
    assert (
        control.public_search_candidate_safety_reason(
            {**safe, "completeSources": 0},
            min_sources=2,
            min_complete_sources=1,
            max_size_bytes=2048,
        )
        == "weak-complete-sources"
    )


def test_public_search_download_proof_triggers_paused_resume_without_leaking_private_values(monkeypatch, tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    delivered = tmp_path / "incoming" / "public-document.pdf"
    delivered.parent.mkdir()
    delivered.write_bytes(b"ok")
    calls: list[tuple[str, str, object]] = []
    stop_calls: list[str] = []
    transfer_reads = 0

    def fake_terms(_inputs: Path, group: str) -> tuple[str, ...]:
        assert group == "documents"
        return ("private search term",)

    def fake_sample(_base_url: str, _api_key: str) -> dict[str, object]:
        return {"ed2kConnected": True, "kadConnected": True}

    def fake_request_json(_base_url: str, path: str, **kwargs) -> dict[str, object]:
        nonlocal transfer_reads
        calls.append((str(kwargs.get("method") or "GET"), path, kwargs.get("body")))
        if path == "/searches":
            return {"id": "search-1"}
        if path.startswith("/searches/search-1?"):
            return {
                "status": "running",
                "items": [
                    {
                        "hash": "0123456789abcdef0123456789abcdef",
                        "name": "public-document.pdf",
                        "sizeBytes": 1024,
                        "fileType": "Doc",
                        "sources": 3,
                        "completeSources": 1,
                        "knownType": "unknown",
                    }
                ],
            }
        if path.endswith("/operations/download"):
            return {"ok": True, "hash": "0123456789abcdef0123456789abcdef"}
        if path.endswith("/operations/resume"):
            return {"ok": True, "hash": "0123456789abcdef0123456789abcdef", "state": "downloading"}
        if path == "/transfers/0123456789abcdef0123456789abcdef":
            transfer_reads += 1
            completed_bytes = 0 if transfer_reads == 1 else 128
            return {
                "hash": "0123456789abcdef0123456789abcdef",
                "name": "public-document.pdf",
                "state": "downloading",
                "sizeBytes": 1024,
                "completedBytes": completed_bytes,
                "sources": 3,
                "sourcesTransferring": 1,
                "progress": completed_bytes / 1024,
                "deliveredPath": str(delivered),
            }
        raise AssertionError(path)

    monkeypatch.setattr(control, "public_search_terms_from_inputs", fake_terms)
    monkeypatch.setattr(control, "sample", fake_sample)
    monkeypatch.setattr(control, "request_json", fake_request_json)
    monkeypatch.setattr(
        control,
        "request_json_attempt",
        lambda _base_url, path, **kwargs: (
            stop_calls.append(path)
            or {"ok": True, "path": path, "method": kwargs.get("method", "GET")}
        ),
    )

    result = control.public_search_download_proof(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="key",
            inputs=tmp_path / "inputs.json",
            term=None,
            term_group="documents",
            search_method="automatic",
            search_type="doc",
            max_terms=4,
            result_limit=50,
            min_sources=2,
            min_complete_sources=1,
            max_size_bytes=8 * 1024 * 1024,
            search_timeout_seconds=1.0,
            progress_timeout_seconds=1.0,
            completion_timeout_seconds=1.0,
            poll_seconds=0.01,
            request_timeout_seconds=1.0,
            require_completion=False,
            stop_search=True,
            progress_jsonl=tmp_path / "progress.jsonl",
        )
    )

    assert result["ok"] is True
    assert calls[0] == (
        "POST",
        "/searches",
        {
            "query": "private search term",
            "method": "automatic",
            "type": "doc",
            "maxSizeBytes": 8 * 1024 * 1024,
            "minAvailability": 2,
        },
    )
    assert ("POST", "/searches/search-1/results/0123456789abcdef0123456789abcdef/operations/download", {"paused": True, "categoryId": 0}) in calls
    assert ("POST", "/transfers/0123456789abcdef0123456789abcdef/operations/resume", {}) in calls
    assert stop_calls == ["/searches/search-1"]
    assert calls.index(("POST", "/searches/search-1/results/0123456789abcdef0123456789abcdef/operations/download", {"paused": True, "categoryId": 0})) < calls.index(("POST", "/transfers/0123456789abcdef0123456789abcdef/operations/resume", {}))
    assert "private search term" not in repr(result)
    assert "public-document.pdf" not in repr(result)
    assert "0123456789abcdef0123456789abcdef" not in repr(result)
    progress_rows = [
        json.loads(line)
        for line in (tmp_path / "progress.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [row["phase"] for row in progress_rows] == [
        "search-started",
        "search-poll",
        "candidate-selected",
        "download-triggered",
        "paused-transfer",
        "resume-triggered",
        "transfer-progress-poll",
        "completion-result",
    ]
    assert "private search term" not in repr(progress_rows)
    assert "public-document.pdf" not in repr(progress_rows)
    assert "0123456789abcdef0123456789abcdef" not in repr(progress_rows)


def test_public_search_download_proof_retries_when_sources_do_not_move_bytes(monkeypatch, tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    first_hash = "11111111111111111111111111111111"
    second_hash = "22222222222222222222222222222222"
    calls: list[tuple[str, str, object]] = []
    stop_calls: list[str] = []
    transfer_reads: dict[str, int] = {first_hash: 0, second_hash: 0}

    def fake_terms(_inputs: Path, group: str) -> tuple[str, ...]:
        assert group == "documents"
        return ("private search term",)

    def fake_sample(_base_url: str, _api_key: str) -> dict[str, object]:
        return {"ed2kConnected": True, "kadConnected": True}

    def fake_request_json(_base_url: str, path: str, **kwargs) -> dict[str, object]:
        calls.append((str(kwargs.get("method") or "GET"), path, kwargs.get("body")))
        if path == "/searches":
            return {"id": "search-1"}
        if path.startswith("/searches/search-1?"):
            return {
                "status": "running",
                "items": [
                    {
                        "hash": first_hash,
                        "name": "public-first.pdf",
                        "sizeBytes": 1024,
                        "fileType": "Doc",
                        "sources": 4,
                        "completeSources": 2,
                    },
                    {
                        "hash": second_hash,
                        "name": "public-second.pdf",
                        "sizeBytes": 1024,
                        "fileType": "Doc",
                        "sources": 3,
                        "completeSources": 1,
                    },
                ],
            }
        if path.endswith("/operations/download"):
            return {"ok": True}
        if path == f"/transfers/{first_hash}/operations/resume":
            return {"ok": True, "hash": first_hash, "state": "downloading"}
        if path == f"/transfers/{second_hash}/operations/resume":
            return {"ok": True, "hash": second_hash, "state": "downloading"}
        if path == f"/transfers/{first_hash}":
            transfer_reads[first_hash] += 1
            return {
                "hash": first_hash,
                "name": "public-first.pdf",
                "state": "downloading",
                "sizeBytes": 1024,
                "completedBytes": 0,
                "sources": 4,
                "sourcesTransferring": 0,
                "progress": 0.0,
            }
        if path == f"/transfers/{second_hash}":
            transfer_reads[second_hash] += 1
            completed_bytes = 0 if transfer_reads[second_hash] == 1 else 256
            return {
                "hash": second_hash,
                "name": "public-second.pdf",
                "state": "downloading",
                "sizeBytes": 1024,
                "completedBytes": completed_bytes,
                "sources": 3,
                "sourcesTransferring": 1,
                "progress": completed_bytes / 1024,
            }
        raise AssertionError(path)

    monkeypatch.setattr(control, "public_search_terms_from_inputs", fake_terms)
    monkeypatch.setattr(control, "sample", fake_sample)
    monkeypatch.setattr(control, "request_json", fake_request_json)
    monkeypatch.setattr(
        control,
        "request_json_attempt",
        lambda _base_url, path, **kwargs: (
            stop_calls.append(path)
            or {"ok": True, "path": path, "method": kwargs.get("method", "GET")}
        ),
    )

    result = control.public_search_download_proof(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="key",
            inputs=tmp_path / "inputs.json",
            term=None,
            term_group="documents",
            search_method="automatic",
            search_type="doc",
            max_terms=1,
            max_download_candidates=2,
            result_limit=50,
            min_sources=2,
            min_complete_sources=1,
            max_size_bytes=8 * 1024 * 1024,
            search_timeout_seconds=1.0,
            progress_timeout_seconds=0.01,
            completion_timeout_seconds=1.0,
            poll_seconds=0.01,
            request_timeout_seconds=1.0,
            require_completion=False,
            stop_search=True,
            progress_jsonl=tmp_path / "progress.jsonl",
        )
    )

    assert result["ok"] is True
    assert len(result["downloadAttempts"]) == 1
    assert result["downloadAttempts"][0]["progress"]["ok"] is False
    assert result["downloadAttempts"][0]["progress"]["sourcesObserved"] is True
    assert result["downloadAttempts"][0]["progress"]["byteProgressObserved"] is False
    assert result["progress"]["byteProgressObserved"] is True
    assert stop_calls == ["/searches/search-1"]
    assert ("POST", f"/searches/search-1/results/{first_hash}/operations/download", {"paused": True, "categoryId": 0}) in calls
    assert ("POST", f"/searches/search-1/results/{second_hash}/operations/download", {"paused": True, "categoryId": 0}) in calls
    assert first_hash not in repr(result)
    assert second_hash not in repr(result)
    assert "public-first.pdf" not in repr(result)
    assert "public-second.pdf" not in repr(result)


def test_public_search_download_cli_writes_json_output(monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    control = _load_rust_soak_control()
    report = tmp_path / "report.json"
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    monkeypatch.setattr(
        control,
        "public_search_download_proof",
        lambda args: {
            "ok": True,
            "jsonOutput": str(args.json_output),
            "searchType": args.search_type,
            "termFingerprint": control.text_fingerprint(args.term),
        },
    )

    assert control.main(
        [
            "public-search-download-proof",
            "--term",
            "private search term",
            "--json-output",
            str(report),
        ]
    ) == 0

    stdout_payload = json.loads(capsys.readouterr().out)
    report_payload = json.loads(report.read_text(encoding="utf-8"))
    assert stdout_payload == report_payload
    assert report_payload["ok"] is True
    assert report_payload["jsonOutput"] == str(report)
    assert report_payload["searchType"] == ""
    assert "private search term" not in report.read_text(encoding="utf-8")


def test_public_search_download_cli_fails_when_report_is_not_ok(
    monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    control = _load_rust_soak_control()
    report = tmp_path / "report.json"
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    monkeypatch.setattr(
        control,
        "public_search_download_proof",
        lambda args: {
            "ok": False,
            "reason": "no-safe-public-candidate",
            "jsonOutput": str(args.json_output),
        },
    )

    assert control.main(["public-search-download-proof", "--json-output", str(report)]) == 1

    stdout_payload = json.loads(capsys.readouterr().out)
    report_payload = json.loads(report.read_text(encoding="utf-8"))
    assert stdout_payload == report_payload
    assert report_payload["ok"] is False
    assert report_payload["reason"] == "no-safe-public-candidate"


def test_public_transfer_debug_summary_sanitizes_transfer_and_sources(monkeypatch) -> None:
    control = _load_rust_soak_control()
    private_hash = "0123456789abcdef0123456789abcdef"
    private_name = "public-document.pdf"
    private_path = r"C:\Private\transfers\public-document.pdf"
    private_client = "198.51.100.9:4662"
    calls: list[str] = []

    def fake_request_json(_base_url: str, path: str, **_kwargs) -> dict[str, object]:
        calls.append(path)
        if path == "/transfers?limit=2&offset=0":
            return {
                "items": [
                    {"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "name": "other.bin"},
                    {
                        "hash": private_hash,
                        "name": private_name,
                        "path": private_path,
                        "state": "downloading",
                        "sizeBytes": 1024,
                        "completedBytes": 0,
                        "sources": 1,
                        "sourcesTransferring": 0,
                    },
                ]
            }
        if path == f"/transfers/{private_hash}/details":
            return {
                "transfer": {},
                "parts": [],
                "sources": [
                    {
                        "clientId": private_client,
                        "userHash": "00112233445566778899aabbccddeeff",
                        "userName": "Private Peer",
                        "clientSoftware": "eMule",
                        "downloadState": "queued",
                        "downloadSpeedKiBps": 0.0,
                        "availableParts": 1,
                        "partCount": 1,
                        "address": private_client,
                        "serverIp": "203.0.113.9",
                        "serverPort": 4661,
                        "lowId": False,
                        "queueRank": 42,
                    }
                ],
            }
        raise AssertionError(path)

    monkeypatch.setattr(control, "request_json", fake_request_json)

    result = control.public_transfer_debug_summary(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="key",
            hash_fingerprint=control.text_fingerprint(private_hash),
            page_limit=2,
            max_offset=10,
            source_sample_limit=5,
            request_timeout_seconds=1.0,
        )
    )

    assert result["ok"] is True
    assert result["sourceStateCounts"] == {"queued": 1}
    assert result["sourceSamples"][0]["clientSoftware"] == "eMule"
    assert result["sourceSamples"][0]["addressPresent"] is True
    assert calls == ["/transfers?limit=2&offset=0", f"/transfers/{private_hash}/details"]
    assert private_hash not in repr(result)
    assert private_name not in repr(result)
    assert private_path not in repr(result)
    assert private_client not in repr(result)
    assert "Private Peer" not in repr(result)


def test_public_transfer_debug_summary_cli_writes_json_output(
    monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    control = _load_rust_soak_control()
    report = tmp_path / "transfer-debug.json"
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    monkeypatch.setattr(
        control,
        "public_transfer_debug_summary",
        lambda args: {
            "ok": True,
            "hashFingerprint": args.hash_fingerprint,
            "jsonOutput": str(args.json_output),
        },
    )

    assert control.main(
        [
            "public-transfer-debug-summary",
            "--hash-fingerprint",
            "abcdef0123456789",
            "--json-output",
            str(report),
        ]
    ) == 0

    stdout_payload = json.loads(capsys.readouterr().out)
    report_payload = json.loads(report.read_text(encoding="utf-8"))
    assert stdout_payload == report_payload
    assert report_payload["hashFingerprint"] == "abcdef0123456789"
    assert report_payload["jsonOutput"] == str(report)


def test_public_search_candidate_wait_stops_on_completed_empty_search(monkeypatch, tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    calls: list[str] = []

    def fake_request_json(_base_url: str, path: str, **_kwargs) -> dict[str, object]:
        calls.append(path)
        if path == "/searches":
            return {"id": "search-1"}
        if path.startswith("/searches/search-1?"):
            return {"status": "complete", "items": []}
        raise AssertionError(path)

    monkeypatch.setattr(control, "request_json", fake_request_json)
    monkeypatch.setattr(
        control,
        "request_json_attempt",
        lambda _base_url, path, **kwargs: {"ok": True, "path": path, "method": kwargs.get("method", "GET")},
    )

    result = control.wait_for_public_search_candidate(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="key",
            search_method="automatic",
            search_type="doc",
            min_sources=2,
            min_complete_sources=1,
            max_size_bytes=8 * 1024 * 1024,
            result_limit=50,
            search_timeout_seconds=60.0,
            poll_seconds=0.01,
            request_timeout_seconds=1.0,
            stop_search=True,
        ),
        "private search term",
    )

    assert result["candidate"] is None
    assert calls == ["/searches", "/searches/search-1?limit=50&includeEvidence=false"]


def test_private_path_fingerprint_normalizes_windows_verbatim_prefix() -> None:
    control = _load_rust_soak_control()

    assert control.private_path_fingerprint(r"\\?\F:\Private\Library") == control.private_path_fingerprint(
        r"F:\Private\Library\\"
    )
    assert control.private_path_fingerprint(r"\\?\UNC\server\share\Library") == control.private_path_fingerprint(
        r"\\server\share\Library"
    )


def test_shared_file_hash_comparison_reports_unique_and_duplicate_gaps() -> None:
    control = _load_rust_soak_control()

    comparison = control.compare_shared_file_hashes(
        {"rowCount": 2, "duplicateHashCount": 0, "hashes": {"a" * 32, "b" * 32}},
        {"rowCount": 3, "duplicateHashCount": 1, "hashes": {"b" * 32, "c" * 32}},
    )

    assert comparison["uniqueHashesMatch"] is False
    assert comparison["rustOnlyUniqueHashCount"] == 1
    assert comparison["mfcOnlyUniqueHashCount"] == 1
    assert comparison["rustDuplicateHashCount"] == 0
    assert comparison["mfcDuplicateHashCount"] == 1
    assert comparison["uniqueHashDeltaRustMinusMfc"] == 0
    assert comparison["rowCountDeltaRustMinusMfc"] == -1


def test_shared_file_catalog_comparison_reports_path_and_hash_gaps() -> None:
    control = _load_rust_soak_control()

    comparison = control.compare_shared_file_catalogs(
        {
            "byPath": {
                "shared": "a" * 32,
                "rust-only": "b" * 32,
                "changed": "c" * 32,
            }
        },
        {
            "byPath": {
                "shared": "a" * 32,
                "mfc-only": "d" * 32,
                "changed": "e" * 32,
            }
        },
    )

    assert comparison["pathFingerprintsMatch"] is False
    assert comparison["rustOnlyPathCount"] == 1
    assert comparison["mfcOnlyPathCount"] == 1
    assert comparison["changedHashForSamePathCount"] == 1
    assert comparison["rustOnlyPathFingerprints"] == ["rust-only"]
    assert comparison["mfcOnlyPathFingerprints"] == ["mfc-only"]
    assert comparison["changedPathFingerprints"] == ["changed"]


def test_shared_file_root_group_comparison_reports_largest_deltas() -> None:
    control = _load_rust_soak_control()

    comparison = control.compare_shared_file_root_groups(
        {
            "groups": [
                {"rootFingerprint": "root-a", "rowCount": 10, "uniqueHashCount": 10},
                {"rootFingerprint": "root-b", "rowCount": 3, "uniqueHashCount": 3},
            ]
        },
        {
            "groups": [
                {"rootFingerprint": "root-a", "rowCount": 12, "uniqueHashCount": 12},
                {"rootFingerprint": "root-c", "rowCount": 7, "uniqueHashCount": 7},
            ]
        },
    )

    assert comparison["rootGroupsMatch"] is False
    assert comparison["differingRootGroupCount"] == 3
    assert comparison["topDeltas"][0]["rootFingerprint"] == "root-c"
    assert comparison["topDeltas"][0]["rowDeltaRustMinusMfc"] == -7


def test_compact_shared_root_catalog_summary_keeps_bounded_top_groups() -> None:
    control = _load_rust_soak_control()

    compact = control.compact_shared_root_catalog_summary(
        {
            "total": 4,
            "rowCount": 4,
            "rootCount": 2,
            "groupCount": 3,
            "groups": [
                {"rootFingerprint": "root-a", "rowCount": 3},
                {"rootFingerprint": "root-b", "rowCount": 1},
                {"rootFingerprint": "root-c", "rowCount": 0},
            ],
        },
        sample_limit=2,
    )

    assert "groups" not in compact
    assert compact["topGroups"] == [
        {"rootFingerprint": "root-a", "rowCount": 3},
        {"rootFingerprint": "root-b", "rowCount": 1},
    ]


def test_unmatched_prefix_groups_are_sanitized_and_bounded() -> None:
    control = _load_rust_soak_control()
    groups = {}

    control.add_unmatched_prefix_groups(groups, r"f:\share\alpha\one.bin", "a" * 32)
    control.add_unmatched_prefix_groups(groups, r"f:\share\alpha\two.bin", "b" * 32)
    control.add_unmatched_prefix_groups(groups, r"g:\share\beta\three.bin", "c" * 32)

    compact = control.compact_unmatched_prefix_groups(groups, sample_limit=1)

    assert compact["depth2"] == [
        {
            "prefixFingerprint": control.private_path_prefix_fingerprint(r"f:\share\alpha\one.bin", 2),
            "rowCount": 2,
            "uniqueHashCount": 2,
        }
    ]
    assert "share" not in str(compact)
    assert "alpha" not in str(compact)


def test_shared_root_for_path_uses_longest_matching_root() -> None:
    control = _load_rust_soak_control()
    roots = [r"f:\share", r"f:\share\nested"]

    assert control.shared_root_for_path(r"f:\share\nested\file.bin", roots) == control.private_path_fingerprint(
        r"f:\share\nested"
    )
    assert control.shared_root_for_path(r"f:\other\file.bin", roots) == "unmatched"


def test_shared_directory_model_persistence_lists_preserve_mfc_semantics() -> None:
    control = _load_rust_soak_control()

    lists = control.shared_directory_model_persistence_lists(
        {
            "roots": [
                {"path": r"C:\Flat", "accessible": True, "shareable": True, "recursive": False},
                {"path": r"C:\Tree", "accessible": True, "shareable": True, "recursive": True},
            ],
            "items": [
                {"path": r"C:\Flat", "accessible": True, "shareable": True, "monitorOwned": False},
                {"path": r"C:\Tree", "accessible": True, "shareable": True, "monitorOwned": False},
                {"path": r"C:\Tree\Child", "accessible": True, "shareable": True, "monitorOwned": True},
                {"path": r"C:\Offline", "accessible": False, "shareable": True, "monitorOwned": False},
            ],
            "monitorOwned": [r"C:\Tree\Child", r"C:\Tree\Missing"],
        }
    )

    assert lists == {
        "shared": ["C:\\Flat\\", "C:\\Tree\\", "C:\\Tree\\Child\\"],
        "monitored": ["C:\\Tree\\"],
        "monitorOwned": ["C:\\Tree\\Child\\"],
    }


def test_write_mfc_shareddir_from_rest_writes_three_profile_files(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    profile_dir = tmp_path / "profile-base"
    config_dir = profile_dir / "config"
    config_dir.mkdir(parents=True)

    monkeypatch.setattr(
        control,
        "request_json",
        lambda *args, **kwargs: {
            "roots": [
                {"path": r"C:\Tree", "accessible": True, "shareable": True, "recursive": True},
            ],
            "items": [
                {"path": r"C:\Tree", "accessible": True, "shareable": True, "monitorOwned": False},
                {"path": r"C:\Tree\Child", "accessible": True, "shareable": True, "monitorOwned": True},
            ],
            "monitorOwned": [r"C:\Tree\Child"],
        },
    )

    result = control.write_mfc_shareddir_from_rest(
        SimpleNamespace(
            source_base_url="http://192.0.2.10:4731/api/v1",
            source_api_key="key",
            target_profile_dir=profile_dir,
            timeout_seconds=1.0,
            fingerprint_sample_limit=3,
            dry_run=False,
        )
    )

    assert result["written"] is True
    assert result["counts"] == {"shared": 2, "monitored": 1, "monitorOwned": 1}
    assert (config_dir / "shareddir.dat").read_text(encoding="utf-16").splitlines() == [
        "C:\\Tree\\",
        "C:\\Tree\\Child\\",
    ]
    assert (config_dir / "shareddir.monitored.dat").read_text(encoding="utf-16").splitlines() == ["C:\\Tree\\"]
    assert (config_dir / "shareddir.monitor-owned.dat").read_text(encoding="utf-16").splitlines() == [
        "C:\\Tree\\Child\\",
    ]


def test_repair_rust_metadata_accepts_extra_shared_roots(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    known_met = tmp_path / "known.met"
    known_met.write_bytes(b"\x00")
    captured = {}

    monkeypatch.setattr(control, "fetch_shared_file_rows", lambda *args, **kwargs: [])
    monkeypatch.setattr(control, "mfc_rest_shared_root_entries", lambda *args, **kwargs: [r"C:\Shared"])

    def fake_import(**kwargs):
        captured["shared_roots"] = kwargs["shared_roots"]
        return {
            "knownMetRecords": 0,
            "sharedFileRows": 0,
            "matchedRows": 0,
            "importedRows": 0,
            "dryRun": True,
            "skipped": {},
        }

    monkeypatch.setattr(control.mfc_known_met, "import_mfc_shared_file_rows_hashes", fake_import)

    result = control.repair_rust_metadata_from_mfc_rest(
        SimpleNamespace(
            known_met=known_met,
            allow_known_met_fallback=False,
            mfc_base_url="http://192.0.2.20:4732/api/v1",
            mfc_api_key="mfc",
            metadata_db=tmp_path / "emulebb-rust-metadata.db",
            rust_repo=tmp_path / "emulebb-rust",
            shared_file_page_size=1000,
            shared_file_timeout_seconds=1.0,
            shared_file_sleep_seconds=0.0,
            extra_root=[Path(r"C:\Incoming")],
            dry_run=True,
        )
    )

    assert result["status"] == "dry-run"
    assert [str(path) for path in captured["shared_roots"]] == ["C:\\Shared", "C:\\Incoming"]


def test_resolve_mfc_start_profile_prefers_existing_persisted_profile(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    profile_dir = tmp_path / "profile-base"
    config_dir = profile_dir / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "preferences.ini").write_text("[eMule]\n", encoding="utf-8")
    monkeypatch.setattr(control, "default_mfc_profile_dir", lambda: profile_dir)

    resolved, mode = control.resolve_mfc_start_profile(
        SimpleNamespace(direct_profile_dir=None, rebuild_profile_from_inputs=False)
    )

    assert resolved == profile_dir
    assert mode == "default-direct"


def test_resolve_mfc_start_profile_allows_explicit_input_rebuild(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    profile_dir = tmp_path / "profile-base"
    config_dir = profile_dir / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "preferences.ini").write_text("[eMule]\n", encoding="utf-8")
    monkeypatch.setattr(control, "default_mfc_profile_dir", lambda: profile_dir)

    resolved, mode = control.resolve_mfc_start_profile(
        SimpleNamespace(direct_profile_dir=None, rebuild_profile_from_inputs=True)
    )

    assert resolved is None
    assert mode == "prepared-from-inputs"


def test_resolve_mfc_start_profile_honors_explicit_direct_profile(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    profile_dir = tmp_path / "explicit-profile"

    resolved, mode = control.resolve_mfc_start_profile(
        SimpleNamespace(direct_profile_dir=profile_dir, rebuild_profile_from_inputs=True)
    )

    assert resolved == profile_dir
    assert mode == "explicit-direct"


def test_mfc_upload_log_discovery_prefers_newest_fresh_candidate(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    stale = logs_dir / "emulebb-diagnostics-upload-slot-old.log"
    fresh = logs_dir / "emulebb-diagnostics-upload-slot.log"
    stale.write_text("old\n", encoding="utf-8")
    fresh.write_text("fresh\n", encoding="utf-8")
    now = time.time()
    os.utime(stale, (now - 3600, now - 3600))
    os.utime(fresh, (now, now))

    candidates = control.mfc_upload_log_candidates([tmp_path], limit=5)
    discovered = control.discover_mfc_upload_log([tmp_path], max_age_seconds=900.0)

    assert [Path(row["path"]).name for row in candidates] == [
        "emulebb-diagnostics-upload-slot.log",
        "emulebb-diagnostics-upload-slot-old.log",
    ]
    assert discovered == fresh.resolve()


def test_fresh_mfc_upload_log_rejects_stale_candidate(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    log_file = tmp_path / "emulebb-diagnostics-upload-slot.log"
    log_file.write_text("stale\n", encoding="utf-8")
    old = time.time() - 3600
    os.utime(log_file, (old, old))

    assert control.fresh_mfc_upload_log(log_file, max_age_seconds=900.0) is None


def test_start_upload_monitor_rejects_explicit_stale_mfc_log(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    rust_log = tmp_path / "emulebb-rust-diag-123.jsonl"
    mfc_log = tmp_path / "emulebb-diagnostics-upload-slot.log"
    rust_log.write_text("{}\n", encoding="utf-8")
    mfc_log.write_text("stale\n", encoding="utf-8")
    old = time.time() - 3600
    os.utime(mfc_log, (old, old))

    with pytest.raises(RuntimeError, match="missing or stale"):
        control.start_upload_monitor(
            SimpleNamespace(
                base_url="http://127.0.0.1:4731/api/v1",
                api_key="test-key",
                output_dir=tmp_path / "monitor",
                log_dir=tmp_path,
                rust_pid=None,
                rust_diag_log=rust_log,
                mfc_upload_log=mfc_log,
                interval_seconds=300.0,
                mfc_log_stale_seconds=900.0,
            )
        )


def test_start_upload_monitor_ignores_stale_reused_mfc_log(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    rust_log = tmp_path / "emulebb-rust-diag-123.jsonl"
    stale_mfc_log = tmp_path / "old" / "emulebb-diagnostics-upload-slot.log"
    fresh_mfc_log = tmp_path / "fresh" / "emulebb-diagnostics-upload-slot.log"
    rust_log.write_text("{}\n", encoding="utf-8")
    stale_mfc_log.parent.mkdir()
    fresh_mfc_log.parent.mkdir()
    stale_mfc_log.write_text("stale\n", encoding="utf-8")
    fresh_mfc_log.write_text("fresh\n", encoding="utf-8")
    old = time.time() - 3600
    os.utime(stale_mfc_log, (old, old))

    commands: list[list[str]] = []

    class FakePopen:
        def __init__(self, command, **kwargs):
            del kwargs
            commands.append(list(command))
            self.pid = 4321

    monkeypatch.setattr(control, "existing_monitor_mfc_upload_log", lambda output_dir: stale_mfc_log)
    monkeypatch.setattr(control, "discover_mfc_upload_log", lambda roots, max_age_seconds: fresh_mfc_log)
    monkeypatch.setattr(control.subprocess, "Popen", FakePopen)

    result = control.start_upload_monitor(
        SimpleNamespace(
            base_url="http://127.0.0.1:4731/api/v1",
            api_key="test-key",
            output_dir=tmp_path / "monitor",
            log_dir=tmp_path,
            rust_pid=None,
            rust_diag_log=rust_log,
            mfc_upload_log=None,
            interval_seconds=300.0,
            mfc_log_stale_seconds=900.0,
        )
    )

    assert result["monitorPid"] == 4321
    assert str(fresh_mfc_log) in commands[0]
    assert str(stale_mfc_log) not in commands[0]


def test_start_upload_monitor_allows_regular_rust_without_diag_log(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    mfc_log = tmp_path / "emulebb-diagnostics-upload-slot.log"
    mfc_log.write_text("fresh\n", encoding="utf-8")
    commands: list[list[str]] = []

    class FakePopen:
        def __init__(self, command, **kwargs):
            del kwargs
            commands.append(list(command))
            self.pid = 5432

    monkeypatch.setattr(control, "latest_diag_log", lambda _log_dir, _rust_pid: None)
    monkeypatch.setattr(control.subprocess, "Popen", FakePopen)

    result = control.start_upload_monitor(
        SimpleNamespace(
            base_url="http://127.0.0.1:4731/api/v1",
            api_key="test-key",
            output_dir=tmp_path / "monitor",
            log_dir=tmp_path,
            rust_pid=123,
            rust_diag_log=None,
            mfc_upload_log=mfc_log,
            interval_seconds=300.0,
            mfc_log_stale_seconds=900.0,
        )
    )

    assert result["monitorPid"] == 5432
    assert result["rustDiagLog"] is None
    assert "--rust-diag-log" not in commands[0]
    assert "--mfc-upload-log" in commands[0]


def test_start_watch_loop_propagates_live_evidence_args(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    commands: list[list[str]] = []

    class FakePopen:
        def __init__(self, command, **kwargs):
            del kwargs
            commands.append(list(command))
            self.pid = 8765

    monkeypatch.setattr(control.subprocess, "Popen", FakePopen)

    rust_diag = tmp_path / "emulebb-rust-diag-123.jsonl"
    mfc_upload = tmp_path / "emulebb-diagnostics-upload-slot.log"
    vpn_exe = tmp_path / "emulebb-rust-diagnostics.exe"
    result = control.start_watch_loop(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="rust-key",
            output_dir=tmp_path / "watch",
            stale_seconds=900.0,
            log_dir=tmp_path / "packet-dump",
            rust_pid=123,
            rust_diag_log=rust_diag,
            mfc_upload_log=mfc_upload,
            mfc_base_url="http://192.0.2.10:4732/api/v1",
            mfc_api_key="mfc-key",
            interval_seconds=300.0,
            mfc_log_stale_seconds=900.0,
            monitor_required=True,
            restart_stale_monitor=True,
            watch_interval_seconds=300.0,
            max_samples=0,
            watch_jsonl=tmp_path / "watch" / "watch.jsonl",
            watch_heartbeat=tmp_path / "watch" / "heartbeat.txt",
            watch_stop_file=tmp_path / "watch" / "watch.stop",
            include_vpn_status=True,
            check_vpn_adapter=True,
            vpn_settings_path=tmp_path / "vpn.json",
            vpn_exe=[vpn_exe],
            diagnostics_log_dir=[],
            diagnostics_log_file=[rust_diag],
            diagnostics_limit=20000,
            diagnostics_max_bytes=4_194_304,
        )
    )

    assert result["watchPid"] == 8765
    command = commands[0]
    assert "watch-loop" in command
    assert ["--mfc-base-url", "http://192.0.2.10:4732/api/v1"] == command[
        command.index("--mfc-base-url") : command.index("--mfc-base-url") + 2
    ]
    assert ["--mfc-api-key", "mfc-key"] == command[command.index("--mfc-api-key") : command.index("--mfc-api-key") + 2]
    assert ["--mfc-upload-log", str(mfc_upload)] == command[
        command.index("--mfc-upload-log") : command.index("--mfc-upload-log") + 2
    ]
    assert ["--rust-diag-log", str(rust_diag)] == command[
        command.index("--rust-diag-log") : command.index("--rust-diag-log") + 2
    ]
    assert ["--diagnostics-log-file", str(rust_diag)] == command[
        command.index("--diagnostics-log-file") : command.index("--diagnostics-log-file") + 2
    ]
    assert "--include-vpn-status" in command
    assert "--check-vpn-adapter" in command
    assert ["--vpn-exe", str(vpn_exe)] == command[command.index("--vpn-exe") : command.index("--vpn-exe") + 2]
    assert ["--diagnostics-limit", "20000"] == command[
        command.index("--diagnostics-limit") : command.index("--diagnostics-limit") + 2
    ]
    assert ["--diagnostics-max-bytes", "4194304"] == command[
        command.index("--diagnostics-max-bytes") : command.index("--diagnostics-max-bytes") + 2
    ]
    assert "--no-monitor-required" not in command


def test_start_profile_watch_loop_uses_profile_watch_paths(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    profile_watch_dir = tmp_path / "rust-runtime" / "live-watch"
    captured: list[SimpleNamespace] = []

    monkeypatch.setattr(
        control,
        "default_profile_launch_watch_paths",
        lambda: {
            "watchPidFile": profile_watch_dir / "rust-soak-watch.pid",
            "watchJsonl": profile_watch_dir / "rust-live-watch.jsonl",
            "watchHeartbeat": profile_watch_dir / "rust-live-watch.heartbeat.txt",
            "watchStopFile": profile_watch_dir / "rust-soak-watch.stop",
        },
    )
    monkeypatch.setattr(control, "start_watch_loop", lambda args: captured.append(args) or {"watchPid": 2468})

    result = control.start_profile_watch_loop(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="rust-key",
            stale_seconds=900.0,
            log_dir=tmp_path / "packet-dump",
            rust_pid=None,
            rust_diag_log=None,
            mfc_upload_log=None,
            mfc_base_url=None,
            mfc_api_key="mfc-key",
            interval_seconds=300.0,
            mfc_log_stale_seconds=900.0,
            monitor_required=False,
            restart_stale_monitor=True,
            watch_interval_seconds=300.0,
            max_samples=0,
            include_vpn_status=True,
            check_vpn_adapter=False,
            vpn_settings_path=None,
            vpn_exe=[],
            diagnostics_log_dir=[],
            diagnostics_log_file=[],
            diagnostics_limit=8,
            diagnostics_max_bytes=262_144,
        )
    )

    assert result["watchPid"] == 2468
    assert captured[0].output_dir == profile_watch_dir
    assert captured[0].watch_jsonl == profile_watch_dir / "rust-live-watch.jsonl"
    assert captured[0].watch_heartbeat == profile_watch_dir / "rust-live-watch.heartbeat.txt"
    assert captured[0].watch_stop_file == profile_watch_dir / "rust-soak-watch.stop"
    assert captured[0].include_vpn_status is True
    assert captured[0].monitor_required is False


def test_stop_profile_watch_loop_uses_profile_watch_paths(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    profile_watch_dir = tmp_path / "rust-runtime" / "live-watch"
    captured: list[SimpleNamespace] = []

    monkeypatch.setattr(
        control,
        "default_profile_launch_watch_paths",
        lambda: {
            "watchPidFile": profile_watch_dir / "rust-soak-watch.pid",
            "watchJsonl": profile_watch_dir / "rust-live-watch.jsonl",
            "watchHeartbeat": profile_watch_dir / "rust-live-watch.heartbeat.txt",
            "watchStopFile": profile_watch_dir / "rust-soak-watch.stop",
        },
    )
    monkeypatch.setattr(control, "stop_watch_loop", lambda args: captured.append(args) or {"stopRequested": True})

    result = control.stop_profile_watch_loop(SimpleNamespace(terminate=True))

    assert result["stopRequested"] is True
    assert captured[0].watch_pid_file == profile_watch_dir / "rust-soak-watch.pid"
    assert captured[0].watch_stop_file == profile_watch_dir / "rust-soak-watch.stop"
    assert captured[0].terminate is True


def test_diagnostics_summary_redacts_live_log_content(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-diagnostics-bad-peer.log"
    jsonl_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    log_file.write_text(
        "\n".join(
            [
                (
                    '{"schema":"bad_peer_event_v1","marker":"BadPeerDiagnostics:",'
                    '"ts_utc":"2026-01-01T00:00:00.000Z","event":"fake_file_search_detected",'
                    '"severity":"medium","action":"warn",'
                    '"file":{"name":"Private Operator Title.mkv","path":"F:\\\\Private\\\\Library"}}'
                ),
                "UPnP mapped ED2K port and Kad port, High ID established",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    jsonl_file.write_text(
        '{"schema":"diag_event_v1","event":"capacity_snapshot","severity":"info"}\n',
        encoding="utf-8",
    )

    result = control.diagnostics_summary(
        SimpleNamespace(log_dir=logs_dir, log_file=None, limit=10, max_bytes=2048)
    )

    assert result["fileCount"] == 2
    assert result["aggregatePatternCounts"]["upnp"] == 1
    assert result["aggregatePatternCounts"]["ed2k"] == 1
    assert result["aggregatePatternCounts"]["kad"] == 1
    assert result["aggregateJsonCounts"]["event"] == {
        "fake_file_search_detected": 1,
        "capacity_snapshot": 1,
    }
    assert result["aggregateJsonCounts"]["severity"] == {"medium": 1, "info": 1}
    event_counts = {
        file_summary["name"]: file_summary["jsonCounts"]["event"]
        for file_summary in result["files"]
        if "jsonCounts" in file_summary
    }
    assert event_counts["emulebb-diagnostics-bad-peer.log"] == {"fake_file_search_detected": 1}
    assert event_counts["emulebb-rust-diag-123.jsonl"] == {"capacity_snapshot": 1}
    rendered = repr(result)
    assert "Private Operator Title" not in rendered
    assert "Private\\Library" not in rendered


def test_diagnostics_summary_combines_multiple_log_dirs(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    rust_logs = tmp_path / "rust"
    mfc_logs = tmp_path / "mfc"
    rust_logs.mkdir()
    mfc_logs.mkdir()
    (rust_logs / "emulebb-rust-diag-123.jsonl").write_text(
        '{"schema":"diag_event_v1","event":"routing_summary","severity":"info","network":"Kad"}\n',
        encoding="utf-8",
    )
    (mfc_logs / "emulebb-diagnostics-packet.log").write_text(
        '{"schema":"ed2k_packet_v1","direction":"out","network":"ED2K"}\n',
        encoding="utf-8",
    )

    result = control.diagnostics_summary(
        SimpleNamespace(log_dir=[rust_logs, mfc_logs], log_file=None, limit=10, max_bytes=2048)
    )

    assert result["fileCount"] == 2
    assert result["logDir"] is None
    assert len(result["logDirs"]) == 2
    assert result["aggregatePatternCounts"]["kad"] == 1
    assert result["aggregatePatternCounts"]["ed2k"] == 1
    assert result["aggregateJsonCounts"]["schema"] == {
        "diag_event_v1": 1,
        "ed2k_packet_v1": 1,
    }
    assert result["aggregateJsonCounts"]["event"] == {"routing_summary": 1}
    rendered = repr(result)
    assert str(rust_logs) not in rendered
    assert str(mfc_logs) not in rendered


def test_diagnostics_summary_reports_safe_body_buckets(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    log_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "upload_slot_recycled",
                        "body": {
                            "reason": "slowUnderfill",
                            "fileName": "Private Operator Title.mkv",
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "upload_request_outcome",
                        "body": {
                            "outcome": "served",
                            "peer": "192.0.2.10:4662",
                            "servedBytes": 184320,
                            "sentPayloadBytes": 184400,
                            "payloadReadMs": 3,
                            "throttleDelayMs": 0,
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "upload_request_outcome",
                        "body": {
                            "outcome": "served",
                            "servedBytes": 92160,
                            "payloadReadMs": 9,
                            "throttleDelayMs": 30,
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "capacity_snapshot",
                        "body": {
                            "activeGrantedSessions": 7,
                            "activeUploadingSessions": 6,
                            "activeNeverUploadedSessions": 1,
                            "activeProductiveSessions": 5,
                            "elasticUnderfill": True,
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = control.diagnostics_summary(
        SimpleNamespace(log_dir=logs_dir, log_file=None, limit=10, max_bytes=2048)
    )

    body_counts = result["files"][0]["jsonBodyCounts"]
    assert body_counts["upload_slot_recycled.reason"] == {"slowUnderfill": 1}
    assert body_counts["upload_request_outcome.outcome"] == {"served": 2}
    assert body_counts["capacity_snapshot.elasticUnderfill"] == {"true": 1}
    body_numeric = result["files"][0]["jsonBodyNumeric"]
    assert body_numeric["upload_request_outcome.servedBytes"] == {
        "count": 2,
        "sum": 276480.0,
        "min": 92160.0,
        "max": 184320.0,
        "average": 138240.0,
    }
    assert body_numeric["capacity_snapshot.activeGrantedSessions"]["sum"] == 7.0
    assert body_numeric["capacity_snapshot.activeUploadingSessions"]["sum"] == 6.0
    assert body_numeric["capacity_snapshot.activeNeverUploadedSessions"]["sum"] == 1.0
    assert body_numeric["capacity_snapshot.activeProductiveSessions"]["sum"] == 5.0
    assert body_numeric["upload_request_outcome.payloadReadMs"]["average"] == 6.0
    assert body_numeric["upload_request_outcome.throttleDelayMs"]["sum"] == 30.0
    rendered = repr(result)
    assert "Private Operator Title" not in rendered
    assert "192.0.2.10" not in rendered


def test_diagnostics_summary_uses_rust_jsonl_ts_field(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    log_file.write_text(
        "\n".join(
            [
                json.dumps({"schema": "diag_event_v1", "event": "capacity_snapshot", "ts": "2026-01-01T00:00:00Z"}),
                json.dumps({"schema": "diag_event_v1", "event": "capacity_snapshot", "ts": "2026-01-01T00:01:00Z"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = control.diagnostics_summary(
        SimpleNamespace(log_dir=logs_dir, log_file=None, limit=10, max_bytes=2048)
    )

    assert result["files"][0]["jsonTimeRange"] == {
        "firstUtc": "2026-01-01T00:00:00+00:00",
        "lastUtc": "2026-01-01T00:01:00+00:00",
    }


def test_upload_efficiency_summary_reports_percentiles_and_redacts_rows(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    rows = [
        {
            "schema": "diag_event_v1",
            "event": "upload_request_outcome",
            "ts": "2026-01-01T00:00:00Z",
            "body": {
                "outcome": "served",
                "peer": "192.0.2.55:4662",
                "fileName": "Private Operator Title.mkv",
                "requestedBytes": 1000,
                "servedBytes": 1000,
                "payloadReadMs": 2,
                "readCacheHits": 2,
                "readCacheMisses": 1,
                "readDiskBytes": 3000,
                "throttleDelayMs": 10,
            },
        },
        {
            "schema": "diag_event_v1",
            "event": "upload_request_outcome",
            "ts": "2026-01-01T00:01:00Z",
            "body": {
                "outcome": "partial",
                "firstSkipReason": "duplicateDone",
                "requestedBytes": 1000,
                "servedBytes": 500,
                "payloadReadMs": 130,
                "readCacheHits": 1,
                "readCacheMisses": 1,
                "readDiskBytes": 1000,
                "throttleDelayMs": 20,
            },
        },
        {
            "schema": "diag_event_v1",
            "event": "upload_request_outcome",
            "ts": "2026-01-01T00:02:00Z",
            "body": {
                "outcome": "served",
                "requestedBytes": 1000,
                "servedBytes": 1000,
                "payloadReadMs": 10,
                "readCacheHits": 0,
                "readCacheMisses": 1,
                "readDiskBytes": 1000,
                "throttleDelayMs": 30,
            },
        },
        {
            "schema": "diag_event_v1",
            "event": "upload_request_outcome",
            "ts": "2026-01-01T00:03:00Z",
            "body": {
                "outcome": "served",
                "requestedBytes": 1000,
                "servedBytes": 1000,
                "payloadReadMs": 400,
                "readCacheHits": 3,
                "readCacheMisses": 1,
                "readDiskBytes": 2000,
                "throttleDelayMs": 40,
            },
        },
    ]
    log_file.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    result = control.upload_efficiency_summary(
        SimpleNamespace(
            log_dir=logs_dir,
            log_file=None,
            limit=10,
            max_bytes=4096,
            slow_read_ms=100.0,
            outlier_limit=2,
        )
    )

    assert result["rowCount"] == 4
    assert result["logDir"] is None
    assert result["logDirFingerprint"] == control.private_path_fingerprint(str(logs_dir))
    assert result["slowReadCount"] == 2
    assert result["slowReadRatio"] == 0.5
    assert result["servedToRequestedRatio"] == 0.875
    assert result["duplicateDoneSuppressedBytes"] == 500.0
    assert result["duplicateDoneSuppressedByteRatio"] == 0.125
    assert result["servedOrDuplicateDoneToRequestedRatio"] == 1.0
    assert result["duplicateDoneAdjustedRequestedBytes"] == 3500.0
    assert result["duplicateDoneAdjustedServedToRequestedRatio"] == 1.0
    assert result["readCacheHitRatio"] == 0.6
    assert result["readDiskToServedRatio"] == 2.0
    assert result["duplicateDoneOutcomeRatio"] == 0.25
    assert result["outcomes"] == {"served": 3, "partial": 1}
    assert result["firstSkipReasons"] == {"duplicateDone": 1}
    read_stats = result["numeric"]["payloadReadMs"]
    assert read_stats["average"] == 135.5
    assert read_stats["p50"] == 70.0
    assert read_stats["p90"] == 319.0
    assert result["numeric"]["readCacheHits"]["sum"] == 6.0
    assert result["numeric"]["readCacheMisses"]["sum"] == 4.0
    assert result["numeric"]["readDiskBytes"]["sum"] == 7000.0
    assert [row["payloadReadMs"] for row in result["worstPayloadReads"]] == [400.0, 130.0]
    assert result["timeRange"] == {
        "firstUtc": "2026-01-01T00:00:00+00:00",
        "lastUtc": "2026-01-01T00:03:00+00:00",
    }
    rendered = repr(result)
    assert "Private Operator Title" not in rendered
    assert "192.0.2.55" not in rendered
    assert str(logs_dir) not in rendered


def test_mfc_upload_summary_reports_payload_counters_and_redacts_rows(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "mfc-logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-diagnostics-upload-slot.log"
    log_file.write_text(
        "\n".join(
            [
                (
                    "2026-01-01 00:00:00 UploadSlotDiagnostics: payload outcome=sent "
                    "peer=198.51.100.10:4662 fileHash=abcdefabcdefabcdefabcdefabcdefab "
                    'fileName="Sample Payload.bin" '
                    "sentFileBytes=1000 sentPayloadBytes=1100 pendingIO=2 "
                    "socketStdQueue=3 rateBytesPerSec=4000"
                ),
                (
                    "2026-01-01 00:00:01 UploadSlotDiagnostics: payload outcome=sent "
                    "peer=198.51.100.11:4662 sourcePath=synthetic/shared/SamplePayload.bin "
                    "sentFileBytes=500 sentPayloadBytes=550 pendingIO=0 "
                    "socketStdQueue=1 rateBytesPerSec=2000"
                ),
                (
                    "2026-01-01 00:00:02 UploadSlotDiagnostics: summary "
                    "server=example.invalid:4661 sharedFiles=1000 ed2kPublishedFiles=950 "
                    "ed2kPendingFiles=50 ed2kPendingLargeUnsupportedFiles=0 ed2kOfferLimit=200 "
                    "kadPublishReady=1 kadSourceDueFiles=20 kadSourceBackoffFiles=980 "
                    "kadSourceSearches=2 kadSourceSearchCap=3 kadKeywordSearches=1 "
                    "kadKeywordSearchCap=2 kadNotesSearches=0 kadNotesSearchCap=1"
                ),
                "2026-01-01 00:00:02 unrelated peer=198.51.100.12",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = control.mfc_upload_summary(
        SimpleNamespace(log_dir=logs_dir, log_file=None, limit=10, max_bytes=4096)
    )

    assert result["rowCount"] == 3
    assert result["logDir"] is None
    assert result["logDirFingerprint"] == control.private_path_fingerprint(str(logs_dir))
    assert result["categories"] == {"payload": 2, "summary": 1}
    assert result["outcomes"] == {"sent": 2}
    assert result["numeric"]["sentFileBytes"]["sum"] == 1500.0
    assert result["numeric"]["sentPayloadBytes"]["sum"] == 1650.0
    assert result["numeric"]["pendingIO"]["max"] == 2.0
    assert result["numeric"]["socketStdQueue"]["average"] == 2.0
    assert result["numeric"]["rateBytesPerSec"]["average"] == 3000.0
    assert result["numeric"]["sharedFiles"]["sum"] == 1000.0
    assert result["numeric"]["ed2kPublishedFiles"]["sum"] == 950.0
    assert result["numeric"]["ed2kPendingFiles"]["sum"] == 50.0
    assert result["numeric"]["ed2kOfferLimit"]["sum"] == 200.0
    assert result["numeric"]["kadSourceDueFiles"]["sum"] == 20.0
    assert result["numeric"]["kadSourceSearchCap"]["sum"] == 3.0
    assert result["fileToPayloadRatio"] == 0.9091
    assert result["payloadOverheadRatio"] == 0.0909
    rendered = repr(result)
    assert "198.51.100" not in rendered
    assert "Sample Payload" not in rendered
    assert "abcdef" not in rendered
    assert "synthetic/shared" not in rendered
    assert str(logs_dir) not in rendered


def test_rust_ed2k_offer_summary_reports_batches_without_hashes(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "rust-logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    log_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "shared_publish_offer_batch",
                        "ts": "2026-01-01T00:00:00Z",
                        "keys": {"server": "203.0.113.10:4661"},
                        "body": {
                            "cursorBefore": 0,
                            "entriesSent": 200,
                            "fileHashes": ["abcdefabcdefabcdefabcdefabcdefab"],
                            "nextCursor": 200,
                            "skippedDuplicateBatch": False,
                            "totalEntries": 1000,
                            "wrapped": False,
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "shared_publish_offer_batch",
                        "ts": "2026-01-01T00:01:00Z",
                        "keys": {"server": "203.0.113.10:4661"},
                        "body": {
                            "cursorBefore": 200,
                            "entriesSent": 200,
                            "fileName": "Private Operator Title.mkv",
                            "nextCursor": 400,
                            "skippedDuplicateBatch": False,
                            "totalEntries": 1000,
                            "wrapped": False,
                        },
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = control.rust_ed2k_offer_summary(
        SimpleNamespace(log_dir=logs_dir, log_file=None, limit=10, max_bytes=4096)
    )

    assert result["rowCount"] == 2
    assert result["observedEntriesSent"] == 400
    assert result["numeric"]["entriesSent"]["sum"] == 400.0
    assert result["numeric"]["totalEntries"]["max"] == 1000.0
    assert result["batchIntervalSeconds"]["average"] == 60.0
    assert result["booleanCounts"]["wrapped"] == {"false": 2}
    assert result["latestBatch"]["nextCursor"] == 400
    rendered = repr(result)
    assert "203.0.113.10" not in rendered
    assert "abcdef" not in rendered
    assert "Private Operator Title" not in rendered
    assert str(logs_dir) not in rendered


def test_anti_flood_summary_groups_sanitized_bursts(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    log_file = logs_dir / "emulebb-rust-diag-123.jsonl"
    log_file.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "anti_flood_drop",
                        "severity": "medium",
                        "ts": "2026-01-01T00:00:00Z",
                        "keys": {"peer": "203.0.113.10:4662"},
                        "body": {
                            "action": "drop",
                            "behavior": "anti_flood_drop",
                            "reason": "tracker_drop",
                            "repeatCount": 3,
                            "windowSeconds": 60,
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "anti_flood_drop",
                        "severity": "medium",
                        "ts": "2026-01-01T00:00:00Z",
                        "keys": {"peer": "203.0.113.10:4662"},
                        "body": {
                            "action": "drop",
                            "behavior": "anti_flood_drop",
                            "reason": "tracker_drop",
                            "repeatCount": 3,
                            "windowSeconds": 60,
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "anti_flood_drop",
                        "severity": "medium",
                        "ts": "2026-01-01T00:00:05Z",
                        "keys": {"peer": "203.0.113.10:4662"},
                        "body": {
                            "action": "drop",
                            "behavior": "anti_flood_drop",
                            "reason": "tracker_drop",
                            "repeatCount": 4,
                            "windowSeconds": 60,
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "anti_flood_ban",
                        "severity": "high",
                        "ts": "2026-01-01T00:01:00Z",
                        "keys": {"peer": "203.0.113.11:4662"},
                        "body": {
                            "action": "drop",
                            "behavior": "anti_flood_ban",
                            "reason": "tracker_massive_drop",
                            "repeatCount": 9,
                            "windowSeconds": 60,
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "udp_packet_v1",
                        "ts": "2026-01-01T00:00:05Z",
                        "peer": "203.0.113.10:4662",
                        "drop_reason": "tracker_drop",
                        "tracker_bucket": "search_req",
                        "tracker_action": "drop",
                        "tracker_observed_packets": 3,
                        "tracker_max_packets": 3,
                        "opcode_name": "KADEMLIA2_SEARCH_SOURCE_REQ",
                    }
                ),
                json.dumps(
                    {
                        "schema": "udp_packet_v1",
                        "ts": "2026-01-01T00:00:05Z",
                        "peer": "203.0.113.10:4662",
                        "drop_reason": "tracker_drop",
                        "tracker_bucket": "publish_source_req",
                        "tracker_action": "drop",
                        "tracker_observed_packets": 3,
                        "tracker_max_packets": 3,
                        "opcode_name": "KADEMLIA2_PUBLISH_SOURCE_REQ",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = control.anti_flood_summary(
        SimpleNamespace(
            log_dir=[logs_dir],
            log_file=None,
            limit=10,
            max_bytes=2048,
            peer_limit=10,
            event_limit=10,
        )
    )

    assert result["totalEvents"] == 3
    assert result["rawEventRows"] == 4
    assert result["duplicateEventRows"] == 1
    assert result["uniquePeers"] == 2
    assert result["maxRepeatCount"] == 9
    assert result["severityCounts"] == {"medium": 2, "high": 1}
    assert result["actionCounts"] == {"drop": 3}
    assert result["behaviorCounts"] == {"anti_flood_drop": 2, "anti_flood_ban": 1}
    assert result["reasonCounts"] == {"tracker_drop": 2, "tracker_massive_drop": 1}
    assert result["windowSecondsCounts"] == {"60": 3}
    assert result["udpTrackerDrops"]["rows"] == 2
    assert result["udpTrackerDrops"]["bucketCounts"] == {
        "search_req": 1,
        "publish_source_req": 1,
    }
    assert result["udpTrackerDrops"]["actionCounts"] == {"drop": 2}
    assert result["udpTrackerDrops"]["reasonCounts"] == {"tracker_drop": 2}
    assert result["udpTrackerDrops"]["recent"][0]["observedPackets"] == 3
    assert result["udpTrackerDrops"]["recent"][0]["maxPackets"] == 3
    assert result["topPeers"][0]["events"] == 2
    assert result["topPeers"][0]["dropEvents"] == 2
    assert result["topPeers"][0]["maxRepeatCount"] == 4
    assert result["recentEvents"][0]["reason"] == "tracker_drop"
    assert result["recentEvents"][-1]["behavior"] == "anti_flood_ban"
    assert result["timeRange"] == {
        "firstUtc": "2026-01-01T00:00:00+00:00",
        "lastUtc": "2026-01-01T00:01:00+00:00",
    }
    rendered = repr(result)
    assert "203.0.113.10" not in rendered
    assert "203.0.113.11" not in rendered


def test_vpn_allowlist_status_reports_sanitized_executable_state(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    exe = tmp_path / "bin" / "emulebb-rust-diagnostics.exe"
    exe.parent.mkdir()
    exe.write_text("placeholder", encoding="utf-8")
    settings = tmp_path / "vpn.settings"
    settings.write_text(
        json.dumps({"SplitTunneling": {"Whitelisted": [{"Path": str(exe)}]}}),
        encoding="utf-8",
    )

    result = control.vpn_allowlist_status(
        SimpleNamespace(exe=[exe], settings_path=settings, check_adapter=False)
    )

    assert result["allWhitelisted"] is True
    assert result["adapterChecked"] is False
    assert result["executables"] == [
        {
            "name": "emulebb-rust-diagnostics.exe",
            "pathFingerprint": control.private_path_fingerprint(str(exe)),
            "exists": True,
            "whitelisted": True,
            "error": "",
        }
    ]
    rendered = repr(result)
    assert str(tmp_path) not in rendered


def test_vpn_allowlist_status_can_default_to_regular_rust_only(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    output_root = tmp_path / "out"
    regular_exe = output_root / "tools" / "emulebb-rust" / "bin" / "emulebb-rust.exe"
    settings = tmp_path / "vpn.settings"
    regular_exe.parent.mkdir(parents=True)
    regular_exe.write_text("placeholder", encoding="utf-8")
    settings.write_text(
        json.dumps({"SplitTunneling": {"Whitelisted": [{"Path": str(regular_exe)}]}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(control, "output_root", lambda: output_root)

    result = control.vpn_allowlist_status(
        SimpleNamespace(
            exe=None,
            rust_regular=True,
            include_mfc=False,
            settings_path=settings,
            check_adapter=False,
        )
    )

    assert result["allWhitelisted"] is True
    assert [row["name"] for row in result["executables"]] == ["emulebb-rust.exe"]


def test_rust_p2p_start_applies_live_wire_network_preferences(monkeypatch) -> None:
    control = _load_rust_soak_control()
    calls: list[tuple[str, str, dict[str, object] | None]] = []

    def fake_request_json(base_url, path, *, api_key, method="GET", body=None, timeout_seconds=8.0):
        assert base_url == "http://192.0.2.10:4731/api/v1"
        assert api_key == "key"
        calls.append((method, path, body))
        return {"ok": True}

    monkeypatch.setattr(control, "request_json", fake_request_json)
    monkeypatch.setattr(control, "sample", lambda _base_url, _api_key: {"ed2kConnected": True, "kadConnected": True})

    result = control.rust_p2p_start(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="key",
            timeout_seconds=1.0,
            ensure_preferences=True,
            start_kad=True,
        )
    )

    assert result["sample"] == {"ed2kConnected": True, "kadConnected": True}
    assert calls == [
        (
            "PATCH",
            "/app/settings",
            {
                "core": {
                    "autoConnect": True,
                    "reconnect": True,
                    "networkKademlia": True,
                    "networkEd2k": True,
                },
            },
        ),
        ("POST", "/kad/operations/start", {}),
        ("POST", "/servers/operations/connect", {}),
    ]


def test_rust_early_connect_proof_requests_start_and_waits_for_highid(monkeypatch) -> None:
    control = _load_rust_soak_control()
    samples = iter(
        [
            {"ed2kConnected": False, "ed2kHighId": False, "kadConnected": False},
            {"ed2kConnected": True, "ed2kHighId": True, "kadConnected": True},
        ]
    )
    p2p_args: list[SimpleNamespace] = []

    def fake_sample(_base_url: str, _api_key: str) -> dict[str, object]:
        return next(samples)

    def fake_p2p_start(args: SimpleNamespace) -> dict[str, object]:
        p2p_args.append(args)
        return {
            "steps": [
                {
                    "ok": True,
                    "method": "PATCH",
                    "path": "/app/settings",
                    "data": {"daemon": {"incomingDir": r"C:\Private\incoming"}},
                },
                {
                    "ok": True,
                    "method": "POST",
                    "path": "/kad/operations/start",
                    "data": {
                        "connected": True,
                        "contactCount": 42,
                        "network": {"vpnGuard": {"publicIp": "198.51.100.10"}},
                    },
                },
            ],
            "sample": {"ed2kConnected": True, "ed2kHighId": False, "kadConnected": True},
        }

    monkeypatch.setattr(control, "sample", fake_sample)
    monkeypatch.setattr(control, "rust_p2p_start", fake_p2p_start)

    result = control.rust_early_connect_proof(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="key",
            timeout_seconds=5.0,
            poll_seconds=0.1,
            request_timeout_seconds=2.0,
            request_start=True,
            ensure_preferences=True,
            start_kad=True,
            require_high_id=True,
            require_kad=True,
        )
    )

    assert result["ok"] is True
    assert p2p_args[0].timeout_seconds == 2.0
    assert p2p_args[0].ensure_preferences is True
    assert p2p_args[0].start_kad is True
    assert result["sample"]["ed2kConnected"] is True
    assert result["sample"]["ed2kHighId"] is True
    assert result["sample"]["kadConnected"] is True
    assert [row["phase"] for row in result["observations"]] == [
        "start-sample",
        "p2p-start-result",
        "poll",
    ]
    rendered = repr(result["p2pStart"])
    assert "C:\\Private" not in rendered
    assert "198.51.100.10" not in rendered


def test_rust_early_connect_proof_times_out_with_missing_checks(monkeypatch) -> None:
    control = _load_rust_soak_control()
    disconnected = {"ed2kConnected": False, "ed2kHighId": False, "kadConnected": False}
    monkeypatch.setattr(control, "sample", lambda _base_url, _api_key: dict(disconnected))

    result = control.rust_early_connect_proof(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="key",
            timeout_seconds=0.0,
            poll_seconds=0.1,
            request_timeout_seconds=2.0,
            request_start=False,
            ensure_preferences=True,
            start_kad=True,
            require_high_id=True,
            require_kad=True,
        )
    )

    assert result["ok"] is False
    assert result["reason"] == "early-connect-timeout"
    assert result["missing"] == ["ed2kConnected", "ed2kHighId", "kadConnected"]


def test_early_connect_cli_writes_json_output(monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    control = _load_rust_soak_control()
    report = tmp_path / "reports" / "early.json"
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    monkeypatch.setattr(
        control,
        "rust_early_connect_proof",
        lambda args: {
            "ok": True,
            "jsonOutput": str(args.json_output),
            "timeoutSeconds": args.timeout_seconds,
            "requireHighId": args.require_high_id,
            "requireKad": args.require_kad,
        },
    )

    assert control.main(["early-connect-proof", "--json-output", str(report)]) == 0

    stdout_payload = json.loads(capsys.readouterr().out)
    report_payload = json.loads(report.read_text(encoding="utf-8"))
    assert stdout_payload == report_payload
    assert report_payload["ok"] is True
    assert report_payload["timeoutSeconds"] == 120.0
    assert report_payload["requireHighId"] is True
    assert report_payload["requireKad"] is True


def test_early_connect_cli_fails_when_report_is_not_ok(
    monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    control = _load_rust_soak_control()
    report = tmp_path / "early.json"
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    monkeypatch.setattr(
        control,
        "rust_early_connect_proof",
        lambda args: {
            "ok": False,
            "reason": "early-connect-timeout",
            "jsonOutput": str(args.json_output),
        },
    )

    assert control.main(["early-connect-proof", "--json-output", str(report)]) == 1

    stdout_payload = json.loads(capsys.readouterr().out)
    report_payload = json.loads(report.read_text(encoding="utf-8"))
    assert stdout_payload == report_payload
    assert report_payload["ok"] is False
    assert report_payload["reason"] == "early-connect-timeout"


def test_regular_log_proof_classifies_logs_and_keeps_report_sanitized(monkeypatch, tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    private_profile = tmp_path / "Private Profile"
    private_db = private_profile / "emulebb-rust-metadata.db"
    private_log_message = (
        r"VPN Guard HTTP public IPv4 probe started from C:\Private\Operator\profile "
        "hash=0123456789abcdef0123456789abcdef"
    )

    def fake_request_json(_base_url: str, path: str, **_kwargs) -> dict[str, object]:
        if path == "/status":
            return {
                "stats": {
                    "uploadSpeedKiBps": 0.0,
                    "activeUploads": 0,
                    "waitingUploads": 0,
                },
                "servers": {
                    "connected": True,
                    "lowId": False,
                },
                "kad": {
                    "connected": True,
                },
                "runtimeDiagnostics": {
                    "ed2kPublish": {
                        "publishedEntries": 50,
                        "pendingEntries": 10,
                    },
                    "kadPublish": {
                        "sourcePublishedTotal": 3,
                    },
                },
            }
        assert path == "/logs?limit=1000"
        return {
            "items": [
                {"timestamp": 10, "level": "info", "message": private_log_message, "debug": False},
                {"timestamp": 11, "level": "info", "message": "VPN Guard STUN probe succeeded", "debug": False},
                {"timestamp": 12, "level": "info", "message": "ED2K server connected with HighID", "debug": False},
                {"timestamp": 13, "level": "info", "message": "Kad connected and publishing", "debug": False},
                {"timestamp": 14, "level": "info", "message": "shared-file publish batch complete", "debug": False},
            ]
        }

    monkeypatch.setattr(control, "request_json", fake_request_json)
    monkeypatch.setattr(
        control,
        "rust_metadata_counts",
        lambda metadata_db: {
            "metadataDb": str(metadata_db),
            "metadataDbExists": True,
            "knownUploadedBytes": 4096,
            "knownUploadAccepts": 2,
            "knownUploadRequests": 2,
            "knownFilesCompleted": 7,
            "transfersTotal": 9,
        },
    )

    result = control.rust_regular_log_proof(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="key",
            limit=1000,
            request_timeout_seconds=2.0,
            inputs=tmp_path / "inputs.json",
            profile_dir=private_profile,
            metadata_db=private_db,
            require_category=None,
            require_high_id=True,
        )
    )

    assert result["ok"] is True
    assert result["logs"]["categoryCounts"]["vpnHttpProbe"] == 1
    assert result["logs"]["categoryCounts"]["vpnStunProbe"] == 1
    assert result["logs"]["categoryCounts"]["ed2k"] == 1
    assert result["logs"]["categoryCounts"]["kad"] == 1
    assert result["logs"]["categoryCounts"]["publish"] >= 1
    assert result["evidence"]["hasUploadHistory"] is True
    assert result["evidence"]["hasDownloadHistory"] is True
    rendered = repr(result)
    assert "Operator" not in rendered
    assert "Private Profile" not in rendered
    assert "0123456789abcdef0123456789abcdef" not in rendered


def test_regular_log_proof_fails_when_required_category_missing(monkeypatch, tmp_path: Path) -> None:
    control = _load_rust_soak_control()

    monkeypatch.setattr(
        control,
        "request_json",
        lambda _base_url, path, **_kwargs: {
            "stats": {},
            "servers": {"connected": True, "lowId": False},
            "kad": {"connected": False},
            "runtimeDiagnostics": {},
        }
        if path == "/status"
        else {
            "items": [
                {"timestamp": 10, "level": "info", "message": "ED2K server connected", "debug": False},
            ]
        },
    )
    monkeypatch.setattr(
        control,
        "rust_metadata_counts",
        lambda _metadata_db: {
            "metadataDb": str(tmp_path / "profile" / "emulebb-rust-metadata.db"),
            "metadataDbExists": True,
            "knownUploadedBytes": 0,
            "knownUploadAccepts": 0,
            "knownUploadRequests": 0,
            "knownFilesCompleted": 0,
            "transfersTotal": 0,
        },
    )

    result = control.rust_regular_log_proof(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="key",
            limit=10,
            request_timeout_seconds=2.0,
            inputs=tmp_path / "inputs.json",
            profile_dir=tmp_path / "profile",
            metadata_db=None,
            require_category=["vpnStunProbe", "kad", "upload"],
            require_high_id=True,
        )
    )

    assert result["ok"] is False
    assert result["missing"] == ["vpnStunProbe", "kad", "upload"]


def test_regular_log_cli_writes_json_output(monkeypatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    control = _load_rust_soak_control()
    report = tmp_path / "reports" / "regular-log.json"
    monkeypatch.setenv("X_LOCAL_IP", "192.0.2.10")

    monkeypatch.setattr(
        control,
        "rust_regular_log_proof",
        lambda args: {
            "ok": True,
            "jsonOutput": str(args.json_output),
            "limit": args.limit,
            "requireHighId": args.require_high_id,
        },
    )

    assert control.main(["regular-log-proof", "--json-output", str(report)]) == 0

    stdout_payload = json.loads(capsys.readouterr().out)
    report_payload = json.loads(report.read_text(encoding="utf-8"))
    assert stdout_payload == report_payload
    assert report_payload["ok"] is True
    assert report_payload["limit"] == 1000
    assert report_payload["requireHighId"] is True


def test_optional_watch_diagnostics_keeps_per_source_summaries(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    rust_logs = tmp_path / "rust"
    mfc_logs = tmp_path / "mfc"
    rust_logs.mkdir()
    mfc_logs.mkdir()
    (rust_logs / "emulebb-rust-diag-1.jsonl").write_text(
        "\n".join(
            [
                '{"schema":"diag_event_v1","event":"packet","severity":"info"} ED2K',
                json.dumps(
                    {
                        "schema": "diag_event_v1",
                        "event": "anti_flood_drop",
                        "severity": "medium",
                        "ts": "2026-01-01T00:00:00Z",
                        "keys": {"peer": "203.0.113.20:4672"},
                        "body": {
                            "action": "drop",
                            "behavior": "anti_flood_drop",
                            "reason": "drop",
                            "repeatCount": 3,
                            "windowSeconds": 60,
                        },
                    }
                ),
                json.dumps(
                    {
                        "schema": "udp_packet_v1",
                        "ts": "2026-01-01T00:00:00Z",
                        "peer": "203.0.113.20:4672",
                        "drop_reason": "tracker_drop",
                        "tracker_bucket": "search_req",
                        "tracker_action": "drop",
                        "tracker_observed_packets": 3,
                        "tracker_max_packets": 3,
                        "opcode_name": "KADEMLIA2_SEARCH_SOURCE_REQ",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (mfc_logs / "emulebb-diagnostics-kad.log").write_text(
        '{"schema":"kad_event_v1","event":"kad_contact_rejected","severity":"info"} Kad firewalled\n',
        encoding="utf-8",
    )

    result = control.optional_watch_diagnostics(
        SimpleNamespace(
            diagnostics_log_dir=[rust_logs, mfc_logs],
            diagnostics_log_file=[],
            diagnostics_limit=4,
            diagnostics_max_bytes=2048,
        )
    )

    assert result is not None
    assert result["fileCount"] == 2
    assert len(result["sources"]) == 2
    assert result["sources"][0]["fileCount"] == 1
    assert result["sources"][1]["fileCount"] == 1
    assert result["aggregatePatternCounts"]["ed2k"] == 1
    assert result["aggregatePatternCounts"]["firewall"] == 1
    assert result["aggregatePatternCounts"]["kad"] == 1
    anti_flood = result["antiFloodSummary"]
    assert anti_flood["totalEvents"] == 1
    assert anti_flood["udpTrackerDrops"]["bucketCounts"] == {"search_req": 1}
    rendered = repr(result)
    assert str(tmp_path) not in rendered
    assert "203.0.113.20" not in rendered


def test_watch_findings_reports_mfc_status_gaps() -> None:
    control = _load_rust_soak_control()

    findings = control.watch_findings(
        {
            "sharedHashingActive": False,
            "sharedHashingCount": 0,
            "ed2kConnected": True,
            "ed2kHighId": True,
            "kadConnected": True,
            "kadFirewalled": False,
        },
        {"monitorAlive": True, "monitorStale": False, "latestRecord": {}},
        {
            "sharedHashingActive": True,
            "sharedHashingCount": 12,
            "ed2kConnected": True,
            "ed2kHighId": False,
            "kadConnected": True,
            "kadFirewalled": True,
        },
    )

    assert "mfc-hashing-active" in findings
    assert "mfc-ed2k-not-high-id" in findings
    assert "mfc-kad-firewalled" in findings


def test_watch_recommendations_preserve_mfc_hashing_before_restart() -> None:
    control = _load_rust_soak_control()

    assert control.watch_recommendations(
        ["mfc-hashing-active", "mfc-ed2k-not-high-id", "mfc-kad-firewalled"],
        {},
        {},
        {"sharedHashingCount": 12},
        {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
    ) == ["preserve-mfc-hashing-before-connectivity-restart"]
    assert control.watch_recommendations(
        ["mfc-ed2k-not-high-id", "mfc-kad-firewalled"],
        {},
        {},
        {"sharedHashingCount": 0},
        {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
    ) == ["restart-mfc-connectivity-path"]
    assert control.watch_recommendations(
        [],
        {},
        {},
        None,
        {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
    ) == ["continue-soak"]
    assert control.watch_recommendations(
        ["rust-anti-flood-ban-observed"],
        {},
        {},
        None,
        {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
    ) == ["continue-soak"]
    assert control.watch_recommendations(
        ["rust-anti-flood-drop-observed"],
        {},
        {},
        None,
        {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
    ) == ["review-rust-anti-flood-diagnostics"]
    assert control.watch_recommendations(
        ["rust-anti-flood-drop-observed", "rust-anti-flood-ban-observed"],
        {},
        {},
        None,
        {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
    ) == ["continue-soak"]


def test_watch_diagnostic_findings_ignore_small_anti_flood_noise() -> None:
    control = _load_rust_soak_control()

    assert (
        control.watch_diagnostic_findings(
            {
                "aggregateJsonCounts": {"event": {"anti_flood_drop": 2}},
                "antiFloodSummary": {
                    "totalEvents": 2,
                    "uniquePeers": 1,
                    "maxRepeatCount": 3,
                    "udpTrackerDrops": {"rows": 0},
                },
            }
        )
        == []
    )
    assert control.watch_diagnostic_findings(
        {
            "aggregateJsonCounts": {"event": {"anti_flood_drop": 10}},
            "antiFloodSummary": {
                "totalEvents": 10,
                "uniquePeers": 1,
                "maxRepeatCount": 8,
                "udpTrackerDrops": {"rows": 0},
            },
        }
    ) == ["rust-anti-flood-hot-peer"]
    assert control.watch_diagnostic_findings(
        {
            "aggregateJsonCounts": {"event": {"anti_flood_drop": 10}},
            "antiFloodSummary": {
                "actionCounts": {"ban": 1, "drop": 10},
                "totalEvents": 11,
                "uniquePeers": 1,
                "maxRepeatCount": 8,
                "udpTrackerDrops": {"rows": 0},
            },
        }
    ) == ["rust-anti-flood-ban-observed"]
    assert control.watch_diagnostic_findings(
        {
            "aggregateJsonCounts": {"event": {"anti_flood_drop": 30}},
            "antiFloodSummary": {
                "totalEvents": 30,
                "uniquePeers": 1,
                "maxRepeatCount": 3,
                "udpTrackerDrops": {"rows": 0},
            },
        }
    ) == ["rust-anti-flood-drop-observed"]
    assert control.watch_diagnostic_findings(
        {
            "aggregateJsonCounts": {"event": {"anti_flood_drop": 1}},
            "antiFloodSummary": {
                "totalEvents": 1,
                "uniquePeers": 1,
                "maxRepeatCount": 1,
                "udpTrackerDrops": {"rows": 1},
            },
        }
    ) == ["rust-anti-flood-drop-observed"]


def test_watch_upload_efficiency_findings_wait_for_visibility_maturity() -> None:
    control = _load_rust_soak_control()
    diagnostics = {
        "uploadEfficiencySummary": {
            "rowCount": 400,
            "duplicateDoneOutcomeRatio": 0.75,
            "servedToRequestedRatio": 0.42,
            "slowReadRatio": 0.02,
        }
    }

    assert (
        control.watch_upload_efficiency_findings(
            {"ed2kPendingEntries": 10, "ed2kVisibilityPercent": 80.0},
            diagnostics,
        )
        == []
    )
    assert control.watch_upload_efficiency_findings(
        {"ed2kPendingEntries": 0, "ed2kVisibilityPercent": 100.0},
        diagnostics,
    ) == ["rust-duplicate-range-pressure"]
    assert (
        control.watch_upload_efficiency_findings(
            {"ed2kPendingEntries": 0, "ed2kVisibilityPercent": 100.0},
            {
                "uploadEfficiencySummary": {
                    "rowCount": 400,
                    "duplicateDoneOutcomeRatio": 0.75,
                    "servedToRequestedRatio": 0.42,
                    "duplicateDoneAdjustedServedToRequestedRatio": 1.0,
                    "servedOrDuplicateDoneToRequestedRatio": 1.0,
                    "slowReadRatio": 0.02,
                }
            },
        )
        == []
    )
    assert control.watch_upload_efficiency_findings(
        {"ed2kPendingEntries": 0, "ed2kVisibilityPercent": 100.0},
        {"uploadEfficiencySummary": {"rowCount": 20, "slowReadRatio": 0.50}},
    ) == []
    assert control.watch_upload_efficiency_findings(
        {"ed2kPendingEntries": 100, "ed2kVisibilityPercent": 10.0},
        {"uploadEfficiencySummary": {"rowCount": 400, "slowReadRatio": 0.20}},
    ) == ["rust-upload-read-slow"]


def test_watch_heartbeat_includes_optional_mfc_status(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    heartbeat = tmp_path / "heartbeat.txt"

    control.write_watch_heartbeat(
        heartbeat,
        {
            "timestampUtc": "2026-01-01T00:00:00+00:00",
            "findings": ["mfc-hashing-active"],
            "recommendations": ["continue-mfc-hashing"],
            "rust": {
                "uploadSpeedKiBps": 1.0,
                "activeUploads": 1,
                "waitingUploads": 0,
                "ed2kPublishedEntries": 2,
                "ed2kPendingEntries": 3,
                "ed2kVisibilityPercent": 4.0,
                "kadFirewalled": False,
            },
            "monitor": {"latestRecord": {"mfcLogStale": False}},
            "uploadDemand": {
                "classification": "visibility-limited",
                "reason": "ed2k-publish-still-maturing",
            },
            "mfc": {
                "uploadSpeedKiBps": 0.5,
                "activeUploads": 1,
                "sharedFileCount": 100,
                "sharedHashingCount": 12,
                "ed2kHighId": False,
                "kadFirewalled": True,
            },
            "vpn": {
                "allWhitelisted": True,
                "adapterUp": True,
                "bindIpPresent": True,
            },
            "diagnostics": {
                "fileCount": 2,
                "aggregatePatternCounts": {"ed2k": 3, "kad": 4},
            },
        },
    )

    text = heartbeat.read_text(encoding="utf-8")
    assert "mfcHashing=12" in text
    assert "mfcEd2kHighId=False" in text
    assert "mfcKadFirewalled=True" in text
    assert "uploadDemandClassification=visibility-limited" in text
    assert "uploadDemandReason=ed2k-publish-still-maturing" in text
    assert "recommendations=continue-mfc-hashing" in text
    assert "vpnAllWhitelisted=True" in text
    assert "vpnAdapterUp=True" in text
    assert "diagnosticsFiles=2" in text
    assert "diagnosticsPatterns=ed2k,kad" in text


def test_watch_trend_summarizes_retained_jsonl_progress(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    records = [
        {
            "timestampUtc": "2026-01-01T00:00:00+00:00",
            "findings": ["mfc-hashing-active"],
            "recommendations": ["continue-mfc-hashing"],
            "rust": {
                "uploadSpeedKiBps": 100.0,
                "activeUploads": 2,
                "ed2kPublishedEntries": 1000,
                "ed2kPendingEntries": 9000,
                "kadSourcePublishedTotal": 10,
            },
            "mfc": {
                "sharedFileCount": 100,
                "sharedHashingCount": 900,
                "uploadSpeedKiBps": 1.0,
                "activeUploads": 1,
            },
            "monitor": {
                "latestRecord": {
                    "rustKiBps": 90.0,
                    "mfcKiBps": 4.0,
                }
            },
        },
        {
            "timestampUtc": "2026-01-01T00:10:00+00:00",
            "findings": ["mfc-hashing-active", "mfc-kad-firewalled"],
            "recommendations": ["preserve-mfc-hashing-before-connectivity-restart"],
            "diagnostics": {
                "files": [
                    {
                        "jsonBodyCounts": {
                            "upload_request_outcome.firstSkipReason": {"duplicateDone": 2},
                            "upload_request_outcome.outcome": {"served": 3},
                            "upload_slot_recycled.reason": {"uploadTimeout": 1},
                        },
                        "jsonBodyNumeric": {
                            "upload_payload_accounting.sentFileBytes": {
                                "count": 3,
                                "sum": 300.0,
                                "min": 50.0,
                                "max": 150.0,
                                "average": 100.0,
                            },
                            "upload_payload_accounting.sentPayloadBytes": {
                                "count": 3,
                                "sum": 330.0,
                                "min": 60.0,
                                "max": 160.0,
                                "average": 110.0,
                            },
                            "upload_request_outcome.servedBytes": {
                                "count": 3,
                                "sum": 300.0,
                                "min": 50.0,
                                "max": 150.0,
                                "average": 100.0,
                            },
                            "upload_request_outcome.requestedBytes": {
                                "count": 3,
                                "sum": 600.0,
                                "min": 100.0,
                                "max": 300.0,
                                "average": 200.0,
                            },
                            "upload_request_outcome.payloadReadMs": {
                                "count": 3,
                                "sum": 12.0,
                                "min": 2.0,
                                "max": 6.0,
                                "average": 4.0,
                            },
                            "upload_request_outcome.throttleDelayMs": {
                                "count": 3,
                                "sum": 15.0,
                                "min": 3.0,
                                "max": 7.0,
                                "average": 5.0,
                            },
                            "upload_request_outcome.readCacheHits": {
                                "count": 3,
                                "sum": 3.0,
                                "min": 0.0,
                                "max": 2.0,
                                "average": 1.0,
                            },
                            "upload_request_outcome.readCacheMisses": {
                                "count": 3,
                                "sum": 2.0,
                                "min": 0.0,
                                "max": 1.0,
                                "average": 0.667,
                            },
                            "upload_request_outcome.readDiskBytes": {
                                "count": 3,
                                "sum": 600.0,
                                "min": 0.0,
                                "max": 300.0,
                                "average": 200.0,
                            }
                        }
                    },
                    {
                        "jsonBodyCounts": {
                            "upload_request_outcome.firstSkipReason": {"duplicateDone": 1},
                            "upload_request_outcome.outcome": {"partial": 1, "served": 2}
                        },
                        "jsonBodyNumeric": {
                            "upload_payload_accounting.sentFileBytes": {
                                "count": 2,
                                "sum": 150.0,
                                "min": 25.0,
                                "max": 125.0,
                                "average": 75.0,
                            },
                            "upload_payload_accounting.sentPayloadBytes": {
                                "count": 2,
                                "sum": 165.0,
                                "min": 30.0,
                                "max": 135.0,
                                "average": 82.5,
                            },
                            "upload_request_outcome.servedBytes": {
                                "count": 2,
                                "sum": 150.0,
                                "min": 25.0,
                                "max": 125.0,
                                "average": 75.0,
                            },
                            "upload_request_outcome.requestedBytes": {
                                "count": 2,
                                "sum": 300.0,
                                "min": 75.0,
                                "max": 225.0,
                                "average": 150.0,
                            },
                            "upload_request_outcome.payloadReadMs": {
                                "count": 2,
                                "sum": 12.0,
                                "min": 4.0,
                                "max": 8.0,
                                "average": 6.0,
                            },
                            "upload_request_outcome.throttleDelayMs": {
                                "count": 2,
                                "sum": 20.0,
                                "min": 8.0,
                                "max": 12.0,
                                "average": 10.0,
                            },
                            "upload_request_outcome.readCacheHits": {
                                "count": 2,
                                "sum": 1.0,
                                "min": 0.0,
                                "max": 1.0,
                                "average": 0.5,
                            },
                            "upload_request_outcome.readCacheMisses": {
                                "count": 2,
                                "sum": 4.0,
                                "min": 2.0,
                                "max": 2.0,
                                "average": 2.0,
                            },
                            "upload_request_outcome.readDiskBytes": {
                                "count": 2,
                                "sum": 900.0,
                                "min": 400.0,
                                "max": 500.0,
                                "average": 450.0,
                            }
                        }
                    },
                ]
            },
            "rust": {
                "uploadSpeedKiBps": 200.0,
                "activeUploads": 4,
                "ed2kPublishedEntries": 1200,
                "ed2kPendingEntries": 8800,
                "kadSourcePublishedTotal": 14,
            },
            "mfc": {
                "sharedFileCount": 160,
                "sharedHashingCount": 840,
                "uploadSpeedKiBps": 2.0,
                "activeUploads": 1,
            },
            "monitor": {
                "latestRecord": {
                    "rustKiBps": 180.0,
                    "mfcKiBps": 10.0,
                }
            },
        },
    ]
    jsonl.write_text("\n".join(control.json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")

    trend = control.watch_trend(SimpleNamespace(watch_jsonl=jsonl, limit=10))

    assert trend["sampleCount"] == 2
    assert trend["window"]["elapsedSeconds"] == 600.0
    assert trend["latestFindings"] == ["mfc-hashing-active", "mfc-kad-firewalled"]
    assert trend["latestRecommendations"] == ["preserve-mfc-hashing-before-connectivity-restart"]
    assert trend["latestDiagnosticsBodyCounts"]["upload_request_outcome.outcome"] == {
        "served": 5,
        "partial": 1,
    }
    assert trend["latestDiagnosticsBodyCounts"]["upload_request_outcome.firstSkipReason"] == {
        "duplicateDone": 3
    }
    assert trend["latestDiagnosticsBodyCounts"]["upload_slot_recycled.reason"] == {"uploadTimeout": 1}
    assert trend["latestDiagnosticsBodyNumeric"]["upload_request_outcome.servedBytes"] == {
        "count": 5,
        "sum": 450.0,
        "min": 25.0,
        "max": 150.0,
        "average": 90.0,
    }
    assert trend["latestUploadEfficiency"]["servedToRequestedRatio"] == 0.5
    assert trend["latestUploadEfficiency"]["payloadOverheadBytes"] == 45.0
    assert trend["latestUploadEfficiency"]["payloadOverheadRatio"] == 0.1
    assert trend["latestUploadEfficiency"]["averagePayloadReadMs"] == 4.8
    assert trend["latestUploadEfficiency"]["averageThrottleDelayMs"] == 7.0
    assert trend["latestUploadEfficiency"]["readCacheHitRatio"] == 0.4
    assert trend["latestUploadEfficiency"]["readDiskToServedRatio"] == 3.3333
    assert trend["latestUploadEfficiency"]["duplicateDoneOutcomeRatio"] == 0.5
    assert trend["counters"]["rustEd2kPublished"]["delta"] == 200.0
    assert trend["counters"]["rustEd2kPublished"]["perMinute"] == 20.0
    assert trend["counters"]["rustEd2kPending"]["perMinute"] == -20.0
    assert trend["counters"]["rustEd2kPending"]["remainingEtaMinutes"] == 440.0
    assert trend["counters"]["rustEd2kPending"]["remainingEtaHours"] == 7.33
    assert trend["counters"]["mfcSharedFiles"]["delta"] == 60.0
    assert trend["counters"]["mfcHashingRemaining"]["delta"] == -60.0
    assert trend["counters"]["mfcHashingRemaining"]["completedDelta"] == 60.0
    assert trend["counters"]["mfcHashingRemaining"]["completedPerMinute"] == 6.0
    assert trend["counters"]["mfcHashingRemaining"]["remainingEtaMinutes"] == 140.0
    assert trend["counters"]["mfcHashingRemaining"]["remainingEtaHours"] == 2.33
    assert trend["counters"]["monitorRustUploadKiBps"]["delta"] == 90.0
    assert trend["counters"]["monitorRustUploadKiBps"]["perMinute"] == 9.0
    assert trend["counters"]["monitorMfcUploadKiBps"]["last"] == 10.0
    assert trend["counters"]["monitorMfcUploadKiBps"]["perMinute"] == 0.6
    assert "remainingEtaMinutes" not in trend["counters"]["monitorMfcUploadKiBps"]


def test_watch_trend_segments_rust_publish_counters_after_restart(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    records = [
        {
            "timestampUtc": "2026-01-01T00:00:00+00:00",
            "rust": {
                "ed2kPublishedEntries": 30000,
                "ed2kPendingEntries": 34000,
                "kadSourcePublishedTotal": 320,
            },
        },
        {
            "timestampUtc": "2026-01-01T00:05:00+00:00",
            "rust": {
                "ed2kPublishedEntries": 400,
                "ed2kPendingEntries": 63600,
                "kadSourcePublishedTotal": 0,
            },
        },
        {
            "timestampUtc": "2026-01-01T00:10:00+00:00",
            "rust": {
                "ed2kPublishedEntries": 600,
                "ed2kPendingEntries": 63400,
                "kadSourcePublishedTotal": 3,
            },
        },
    ]
    jsonl.write_text("\n".join(control.json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")

    trend = control.watch_trend(SimpleNamespace(watch_jsonl=jsonl, limit=10))

    published = trend["counters"]["rustEd2kPublished"]
    assert published["first"] == 400.0
    assert published["last"] == 600.0
    assert published["delta"] == 200.0
    assert published["perMinute"] == 40.0
    assert published["resetSegment"] is True
    assert published["droppedSamples"] == 1

    pending = trend["counters"]["rustEd2kPending"]
    assert pending["first"] == 63600.0
    assert pending["last"] == 63400.0
    assert pending["delta"] == -200.0
    assert pending["perMinute"] == -40.0
    assert pending["remainingEtaMinutes"] == 1585.0
    assert pending["resetSegment"] is True

    kad = trend["counters"]["rustKadSourcePublished"]
    assert kad["first"] == 0.0
    assert kad["last"] == 3.0
    assert kad["delta"] == 3.0
    assert kad["resetSegment"] is True


def test_watch_status_flags_stale_retained_sample(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    pid_file = tmp_path / "watch.pid"
    jsonl = tmp_path / "watch.jsonl"
    heartbeat = tmp_path / "watch.heartbeat.txt"
    stop_file = tmp_path / "watch.stop"
    pid_file.write_text("1234\n", encoding="utf-8")
    heartbeat.write_text("old heartbeat\n", encoding="utf-8")
    jsonl.write_text(
        control.json.dumps({"timestampUtc": "2026-01-01T00:00:00+00:00"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(control, "pid_exists", lambda pid: True)
    monkeypatch.setattr(control, "timestamp_age_seconds", lambda timestamp: 901.0)

    status = control.watch_status(
        SimpleNamespace(
            watch_pid_file=pid_file,
            watch_jsonl=jsonl,
            watch_heartbeat=heartbeat,
            watch_stop_file=stop_file,
            stale_seconds=900.0,
        )
    )

    assert status["watchAlive"] is True
    assert status["watchStale"] is True
    assert status["latestAgeSeconds"] == 901.0
    assert status["findings"] == ["watch-stale"]


def test_watch_processes_returns_sanitized_argument_presence(monkeypatch) -> None:
    control = _load_rust_soak_control()
    process = SimpleNamespace(
        pid=8765,
        parent_pid=111,
        name="python.exe",
        creation_date="20260101000000.000000+000",
        command_line=(
            "python rust-soak-control.py --base-url http://192.0.2.10:4731/api/v1 "
            "--api-key private-rust watch-loop --mfc-base-url http://192.0.2.10:4732/api/v1 "
            "--mfc-api-key private-mfc --mfc-upload-log C:\\Private\\mfc.log "
            "--rust-diag-log C:\\Private\\rust.jsonl --diagnostics-log-file C:\\Private\\rust.jsonl "
            "--include-vpn-status --check-vpn-adapter"
        ),
    )
    monkeypatch.setattr(control, "collect_processes", lambda: [process])

    result = control.watch_processes(SimpleNamespace())

    assert result["processes"] == [
        {
            "pid": 8765,
            "parentPid": 111,
            "name": "python.exe",
            "creationDate": "20260101000000.000000+000",
            "commandLineFingerprint": result["processes"][0]["commandLineFingerprint"],
            "hasWatchLoop": True,
            "hasMfcBaseUrl": True,
            "hasMfcApiKey": True,
            "hasMfcUploadLog": True,
            "hasRustDiagLog": True,
            "hasDiagnosticsLogFile": True,
            "hasDiagnosticsLogDir": False,
            "diagnosticsLogFileArgs": 1,
            "includeVpnStatus": True,
            "checkVpnAdapter": True,
            "commandLineLength": len(process.command_line),
        }
    ]
    assert "Private" not in control.json.dumps(result)
    assert "private-mfc" not in control.json.dumps(result)


def test_mfc_processes_only_reports_client_executables(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    profile_dir = tmp_path / "mfc-profile"
    known_met = profile_dir / "config" / "known.met"
    known_met.parent.mkdir(parents=True)
    known_met.write_bytes(b"known")
    client_process = SimpleNamespace(
        pid=2345,
        parent_pid=111,
        name="emulebb-diagnostics.exe",
        creation_date="20260101000000.000000+000",
        command_line=f'emulebb-diagnostics.exe -c "{profile_dir}"',
    )
    helper_process = SimpleNamespace(
        pid=3456,
        parent_pid=111,
        name="python.exe",
        creation_date="20260101000001.000000+000",
        command_line=f"python helper.py --mfc-exe emulebb-diagnostics.exe -c {profile_dir}",
    )
    rust_process = SimpleNamespace(
        pid=4567,
        parent_pid=111,
        name="emulebb-rust-diagnostics.exe",
        creation_date="20260101000002.000000+000",
        command_line="emulebb-rust-diagnostics.exe --profile runtime",
    )
    monkeypatch.setattr(control, "collect_processes", lambda: [helper_process, rust_process, client_process])

    result = control.mfc_processes(SimpleNamespace())

    assert [row["pid"] for row in result["processes"]] == [2345]
    assert result["processes"][0]["hasProfileArg"] is True
    assert result["processes"][0]["knownMetPresent"] is True


def test_discover_mfc_known_met_ignores_helper_command_lines(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    profile_dir = tmp_path / "mfc-profile"
    known_met = profile_dir / "config" / "known.met"
    known_met.parent.mkdir(parents=True)
    known_met.write_bytes(b"known")
    helper_process = SimpleNamespace(
        name="python.exe",
        command_line=f"python helper.py --mfc-exe emulebb-diagnostics.exe -c {profile_dir}",
    )
    client_process = SimpleNamespace(
        name="emulebb-diagnostics.exe",
        command_line=f'emulebb-diagnostics.exe -c "{profile_dir}"',
    )
    monkeypatch.setattr(control, "collect_processes", lambda: [helper_process, client_process])

    assert control.discover_mfc_known_met_from_processes() == known_met


def test_stop_watch_processes_terminates_only_watch_loop_rows(monkeypatch) -> None:
    control = _load_rust_soak_control()
    watch_process = SimpleNamespace(
        pid=8765,
        parent_pid=111,
        name="python.exe",
        creation_date="20260101000000.000000+000",
        command_line="python rust-soak-control.py watch-loop --diagnostics-log-file C:\\Private\\rust.jsonl",
    )
    other_process = SimpleNamespace(
        pid=9999,
        parent_pid=111,
        name="python.exe",
        creation_date="20260101000000.000000+000",
        command_line="python unrelated.py",
    )
    terminated: list[tuple[int, tuple[str, ...], float]] = []

    def fake_terminate(pid: int, *, markers: tuple[str, ...], timeout_seconds: float) -> None:
        terminated.append((pid, markers, timeout_seconds))

    monkeypatch.setattr(control, "collect_processes", lambda: [watch_process, other_process])
    monkeypatch.setattr(control, "terminate_pid_tree", fake_terminate)
    monkeypatch.setattr(control, "pid_exists", lambda pid: pid != 8765)

    result = control.stop_watch_processes(SimpleNamespace(pid=None, timeout_seconds=7.0, dry_run=False))

    assert terminated == [(8765, ("rust-soak-control.py", "watch-loop"), 7.0)]
    assert result["stoppedCount"] == 1
    assert result["processes"][0]["pid"] == 8765
    assert result["processes"][0]["stopped"] is True


def test_stop_profile_launch_terminates_manifest_launcher_tree(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    manifest = tmp_path / "rust-regular-soak.latest.json"
    manifest.write_text(json.dumps({"pid": 4321}), encoding="utf-8")
    launcher = SimpleNamespace(
        pid=4321,
        parent_pid=111,
        name="python.exe",
        creation_date="20260101000000.000000+000",
        command_line="python scripts/launch-soak.py --rust-regular",
    )
    rust = SimpleNamespace(
        pid=5432,
        parent_pid=4321,
        name="emulebb-rust.exe",
        creation_date="20260101000001.000000+000",
        command_line="emulebb-rust.exe --profile C:\\soak\\rust-runtime",
    )
    live_pids = {4321, 5432}
    terminated: list[tuple[int, tuple[str, ...], float]] = []

    def fake_terminate(pid: int, *, markers: tuple[str, ...], timeout_seconds: float) -> None:
        terminated.append((pid, markers, timeout_seconds))
        live_pids.clear()

    monkeypatch.setattr(control, "collect_processes", lambda: [p for p in (launcher, rust) if p.pid in live_pids])
    monkeypatch.setattr(control, "pid_exists", lambda pid: pid in live_pids)
    monkeypatch.setattr(control, "terminate_pid_tree", fake_terminate)

    result = control.stop_profile_launch(SimpleNamespace(manifest=manifest, timeout_seconds=9.0))

    assert terminated == [(4321, ("launch-soak.py",), 9.0)]
    assert result["launcherPid"] == 4321
    assert result["launcherStopped"] is True
    assert result["rustProcessCountBefore"] == 1
    assert result["rustProcessCountAfter"] == 0


def test_profile_status_reports_manifest_processes_and_metadata_counts(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    output_root = tmp_path / "out"
    profile_dir = output_root / "soak" / "rust-runtime"
    metadata_db = profile_dir / "emulebb-rust-metadata.db"
    manifest = tmp_path / "rust-regular-soak.latest.json"
    inputs = tmp_path / "live-wire-inputs.local.json"
    profile_dir.mkdir(parents=True)
    inputs.write_text(
        json.dumps(
            {
                "schema": "emulebb-build-tests.live-wire-inputs.v1",
                "rust_profile": {"profile_dir": str(profile_dir)},
                "search_terms": {
                    "generic_open": ["linux iso"],
                    "documents": ["linux pdf"],
                    "radarr_movies": ["public domain"],
                },
                "auto_browse": {
                    "bootstrap_transfer_hashes": ["0123456789abcdef0123456789abcdef"],
                    "direct_bootstrap_transfers": [
                        {
                            "hash": "0123456789abcdef0123456789abcdef",
                            "name": "fixture.iso",
                            "size": 123,
                            "method": "direct_ed2k",
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    manifest.write_text(
        json.dumps(
            {
                "pid": 4321,
                "startedUtc": "20260716T000000Z",
                "stdout": str(tmp_path / "out.log"),
                "stderr": str(tmp_path / "err.log"),
                "seconds": 3600,
                "lanBindAddr": "192.0.2.10",
            }
        ),
        encoding="utf-8",
    )
    connection = sqlite3.connect(metadata_db)
    try:
        connection.execute("CREATE TABLE known_files (completed INTEGER, size INTEGER, uploaded_bytes INTEGER, upload_requests INTEGER, upload_accepts INTEGER)")
        connection.execute("INSERT INTO known_files VALUES (1, 100, 10, 2, 1)")
        connection.execute("INSERT INTO known_files VALUES (0, 200, 20, 3, 2)")
        connection.execute("CREATE TABLE shared_directory_roots (enabled INTEGER, accessible INTEGER, deleted_at_ms INTEGER)")
        connection.execute("INSERT INTO shared_directory_roots VALUES (1, 1, NULL)")
        connection.execute("INSERT INTO shared_directory_roots VALUES (1, 0, NULL)")
        connection.execute("INSERT INTO shared_directory_roots VALUES (0, 1, NULL)")
        connection.execute("INSERT INTO shared_directory_roots VALUES (1, 1, 123)")
        for table in (
            "transfers",
            "servers",
            "kad_bootstrap_endpoints",
            "peers",
            "transfer_sources",
            "ed2k_part_hashes",
            "aich_part_hashes",
            "kad_keyword_publishes",
            "kad_source_publishes",
        ):
            connection.execute(f"CREATE TABLE {table} (id INTEGER)")
            connection.execute(f"INSERT INTO {table} VALUES (1)")
        connection.commit()
    finally:
        connection.close()
    launcher = SimpleNamespace(
        pid=4321,
        parent_pid=111,
        name="python.exe",
        creation_date="20260101000000.000000+000",
        command_line="python scripts/launch-soak.py --rust-regular",
    )
    rust = SimpleNamespace(
        pid=5432,
        parent_pid=4321,
        name="emulebb-rust.exe",
        creation_date="20260101000001.000000+000",
        command_line=f"emulebb-rust.exe --profile {profile_dir}",
    )
    monkeypatch.setattr(control, "output_root", lambda: output_root)
    monkeypatch.setattr(control, "collect_processes", lambda: [launcher, rust])
    monkeypatch.setattr(control, "pid_exists", lambda pid: pid in {4321, 5432})

    result = control.rust_profile_status(
        SimpleNamespace(
            inputs=inputs,
            profile_dir=None,
            manifest=manifest,
            stale_seconds=900.0,
            include_vpn_status=False,
            check_vpn_adapter=False,
            vpn_settings_path=None,
        )
    )

    assert result["profileDir"] == str(profile_dir)
    assert result["manifest"]["pid"] == 4321
    assert result["launcherProcesses"][0]["hasLaunchSoak"] is True
    assert result["rustProcesses"][0]["pid"] == 5432
    assert result["metadata"]["knownFilesTotal"] == 2
    assert result["metadata"]["knownFilesCompleted"] == 1
    assert result["metadata"]["knownCompletedBytes"] == 100
    assert result["metadata"]["knownUploadedBytes"] == 30
    assert result["metadata"]["knownUploadRequests"] == 5
    assert result["metadata"]["sharedRootsTotal"] == 4
    assert result["metadata"]["sharedRootsEnabled"] == 3
    assert result["metadata"]["sharedRootsAccessibleEnabled"] == 2
    assert result["metadata"]["sharedRootsActive"] == 3
    assert result["metadata"]["sharedRootsActiveEnabled"] == 2
    assert result["metadata"]["sharedRootsActiveAccessibleEnabled"] == 1
    assert result["metadata"]["ed2kPartHashRows"] == 1
    assert result["watch"]["findings"] == ["watch-not-running", "watch-stale"]


def test_set_shared_publish_priority_split_updates_only_matching_root(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    metadata_db = tmp_path / "metadata.sqlite"
    connection = sqlite3.connect(metadata_db)
    try:
        connection.execute(
            """
            CREATE TABLE known_files (
                id INTEGER PRIMARY KEY,
                completed INTEGER,
                upload_priority TEXT,
                auto_upload_priority INTEGER,
                updated_at_ms INTEGER
            )
            """
        )
        connection.execute("CREATE TABLE local_paths (id INTEGER PRIMARY KEY, display_path TEXT)")
        connection.execute("CREATE TABLE shared_file_sources (known_file_id INTEGER, path_id INTEGER)")
        connection.execute("CREATE TABLE unshared_files (known_file_id INTEGER)")
        rows = [
            (1, "F:/share/keep/a.bin"),
            (2, "F:/share/keep/nested/b.bin"),
            (3, "F:/share/other/c.bin"),
        ]
        for known_file_id, path in rows:
            connection.execute(
                "INSERT INTO known_files VALUES (?, 1, 'normal', 1, 0)",
                (known_file_id,),
            )
            connection.execute("INSERT INTO local_paths VALUES (?, ?)", (known_file_id, path))
            connection.execute("INSERT INTO shared_file_sources VALUES (?, ?)", (known_file_id, known_file_id))
        connection.execute("INSERT INTO local_paths VALUES (4, 'F:/share/other/duplicate-b.bin')")
        connection.execute("INSERT INTO shared_file_sources VALUES (2, 4)")
        connection.execute("INSERT INTO known_files VALUES (5, 1, 'normal', 1, 0)")
        connection.commit()
    finally:
        connection.close()

    result = control.set_shared_publish_priority_split(
        SimpleNamespace(
            metadata_db=metadata_db,
            high_root=Path("F:/share/keep"),
            allow_empty_high_root=False,
            dry_run=False,
        )
    )

    assert result["highPrioritySourceRows"] == 2
    assert result["notPublishedSourceRows"] == 2
    assert result["noSourceSharedFiles"] == 1
    assert result["matchedSharedFiles"] == 4
    assert result["highPriorityFiles"] == 2
    assert result["notPublishedFiles"] == 2
    assert result["changedFiles"] == 4
    assert "F:/share/keep" not in json.dumps(result)
    with sqlite3.connect(metadata_db) as conn:
        priorities = dict(conn.execute("SELECT id, upload_priority FROM known_files").fetchall())
        auto = dict(conn.execute("SELECT id, auto_upload_priority FROM known_files").fetchall())
    assert priorities == {1: "high", 2: "high", 3: "not-published", 5: "not-published"}
    assert auto == {1: 0, 2: 0, 3: 0, 5: 0}


def test_set_shared_publish_priority_split_refuses_empty_high_root(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    metadata_db = tmp_path / "metadata.sqlite"
    connection = sqlite3.connect(metadata_db)
    try:
        connection.execute(
            """
            CREATE TABLE known_files (
                id INTEGER PRIMARY KEY,
                completed INTEGER,
                upload_priority TEXT,
                auto_upload_priority INTEGER,
                updated_at_ms INTEGER
            )
            """
        )
        connection.execute("CREATE TABLE local_paths (id INTEGER PRIMARY KEY, display_path TEXT)")
        connection.execute("CREATE TABLE shared_file_sources (known_file_id INTEGER, path_id INTEGER)")
        connection.execute("CREATE TABLE unshared_files (known_file_id INTEGER)")
        connection.execute("INSERT INTO known_files VALUES (1, 1, 'normal', 0, 0)")
        connection.execute("INSERT INTO local_paths VALUES (1, 'F:/share/other/c.bin')")
        connection.execute("INSERT INTO shared_file_sources VALUES (1, 1)")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="matched no shared source rows"):
        control.set_shared_publish_priority_split(
            SimpleNamespace(
                metadata_db=metadata_db,
                high_root=Path("F:/share/keep"),
                allow_empty_high_root=False,
                dry_run=False,
            )
        )


def test_watch_brief_keeps_regular_monitoring_output_compact(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    pid_file = tmp_path / "watch.pid"
    jsonl = tmp_path / "watch.jsonl"
    stop_file = tmp_path / "watch.stop"
    pid_file.write_text("1234\n", encoding="utf-8")
    records = [
        {
            "timestampUtc": "2026-01-01T00:00:00+00:00",
            "rust": {
                "uploadSpeedKiBps": 100.0,
                "activeUploads": 2,
                "waitingUploads": 1,
                "ed2kPublishedEntries": 1000,
                "ed2kPendingEntries": 9000,
                "kadSourcePublishedTotal": 10,
            },
            "mfc": {
                "sharedFileCount": 100,
                "sharedHashingCount": 900,
                "uploadSpeedKiBps": 1.0,
                "activeUploads": 1,
            },
            "monitor": {"latestRecord": {"rustKiBps": 90.0, "mfcKiBps": 2.0}},
        },
        {
            "timestampUtc": "2026-01-01T00:10:00+00:00",
            "findings": ["mfc-hashing-active"],
            "recommendations": ["preserve-mfc-hashing-before-connectivity-restart"],
            "diagnostics": {
                "fileCount": 2,
                "aggregatePatternCounts": {"ed2k": 3},
                "aggregateJsonCounts": {
                    "event": {"upload_request_outcome": 2, "anti_flood_drop": 1},
                    "severity": {"info": 2, "medium": 1},
                },
                "rustEd2kOfferSummary": {
                    "source": "rustDiagLog",
                    "rowCount": 2,
                    "observedEntriesSent": 400,
                    "latestBatch": {
                        "entriesSent": 200,
                        "totalEntries": 1000,
                        "nextCursor": 400,
                        "wrapped": False,
                    },
                    "batchIntervalSeconds": {"count": 1, "average": 60.0},
                },
                "antiFloodSummary": {
                    "totalEvents": 1,
                    "maxRepeatCount": 3,
                    "actionCounts": {"drop": 1},
                    "behaviorCounts": {"anti_flood_drop": 1},
                    "reasonCounts": {"drop": 1},
                    "windowSecondsCounts": {"60": 1},
                    "recentEvents": [{"peerFingerprint": "abc"}],
                    "udpTrackerDrops": {
                        "rows": 2,
                        "bucketCounts": {"search_req": 1, "publish_source_req": 1},
                        "actionCounts": {"drop": 2},
                        "reasonCounts": {"tracker_drop": 2},
                        "opcodeCounts": {
                            "KADEMLIA2_SEARCH_SOURCE_REQ": 1,
                            "KADEMLIA2_PUBLISH_SOURCE_REQ": 1,
                        },
                        "recent": [{"peerFingerprint": "abc"}],
                    },
                },
                "files": [
                    {
                        "jsonBodyCounts": {
                            "upload_request_outcome.firstSkipReason": {"duplicateDone": 1},
                            "upload_request_outcome.outcome": {"partial": 1, "served": 1},
                        },
                        "jsonBodyNumeric": {
                            "upload_payload_accounting.sentFileBytes": {
                                "count": 2,
                                "sum": 200.0,
                                "min": 50.0,
                                "max": 150.0,
                                "average": 100.0,
                            },
                            "upload_payload_accounting.sentPayloadBytes": {
                                "count": 2,
                                "sum": 210.0,
                                "min": 55.0,
                                "max": 155.0,
                                "average": 105.0,
                            },
                            "upload_request_outcome.requestedBytes": {
                                "count": 2,
                                "sum": 400.0,
                                "min": 100.0,
                                "max": 300.0,
                                "average": 200.0,
                            },
                            "upload_request_outcome.servedBytes": {
                                "count": 2,
                                "sum": 200.0,
                                "min": 50.0,
                                "max": 150.0,
                                "average": 100.0,
                            },
                        },
                    }
                ],
            },
            "rust": {
                "uploadSpeedKiBps": 200.0,
                "activeUploads": 4,
                "waitingUploads": 0,
                "ed2kConnected": True,
                "ed2kHighId": True,
                "ed2kPublishedEntries": 1200,
                "ed2kPendingEntries": 8800,
                "ed2kVisibilityPercent": 12.0,
                "kadConnected": True,
                "kadFirewalled": False,
                "kadSourcePublishedTotal": 14,
            },
            "mfc": {
                "sharedFileCount": 160,
                "sharedHashingCount": 840,
                "uploadSpeedKiBps": 2.0,
                "activeUploads": 1,
                "ed2kConnected": True,
                "ed2kHighId": False,
                "kadConnected": True,
                "kadFirewalled": True,
            },
            "monitor": {
                "monitorAlive": True,
                "monitorStale": False,
                "latestAgeSeconds": 20.0,
                "latestRecord": {
                    "rustKiBps": 180.0,
                    "rustUploads": 4,
                    "mfcKiBps": 10.0,
                    "mfcWaiting": 0,
                    "parityGap": False,
                    "mfcLogStale": False,
                },
            },
            "mfcUploadSummary": {
                "source": "mfcUploadSlotLog",
                "rowCount": 8,
                "categories": {"payload": 8},
                "outcomes": {"sent": 8},
                "pendingIO": {"count": 8, "sum": 2.0, "average": 0.25, "max": 1.0},
                "socketStdQueue": {"count": 8, "sum": 4.0, "average": 0.5, "max": 2.0},
                "fileToPayloadRatio": 0.99,
                "payloadOverheadRatio": 0.01,
            },
            "vpn": {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
        },
    ]
    jsonl.write_text("\n".join(control.json.dumps(record, sort_keys=True) for record in records) + "\n", encoding="utf-8")
    monkeypatch.setattr(control, "pid_exists", lambda pid: True)
    monkeypatch.setattr(control, "timestamp_age_seconds", lambda timestamp: 60.0)

    brief = control.watch_brief(
        SimpleNamespace(
            watch_pid_file=pid_file,
            watch_jsonl=jsonl,
            watch_stop_file=stop_file,
            stale_seconds=900.0,
            limit=10,
        )
    )

    assert brief["watch"]["alive"] is True
    assert brief["watch"]["stale"] is False
    assert brief["findings"] == ["mfc-hashing-active", "rust-anti-flood-drop-observed"]
    assert brief["rust"]["uploadSpeedKiBps"] == 200.0
    assert brief["rust"]["ed2kHighId"] is True
    assert brief["mfc"]["sharedHashingCount"] == 840
    assert brief["mfc"]["kadFirewalled"] is True
    assert brief["monitor"]["rustKiBps"] == 180.0
    assert brief["uploadDemand"]["classification"] == "visibility-limited"
    assert brief["uploadDemand"]["reason"] == "ed2k-publish-still-maturing"
    assert brief["uploadDemand"]["ed2kVisibilityPercent"] == 12.0
    assert brief["vpn"]["allWhitelisted"] is True
    assert brief["diagnostics"]["jsonCounts"]["event"]["anti_flood_drop"] == 1
    assert brief["diagnostics"]["uploadEfficiency"]["servedToRequestedRatio"] == 0.5
    assert brief["diagnostics"]["mfcUpload"]["rowCount"] == 8
    assert brief["diagnostics"]["mfcUpload"]["outcomes"] == {"sent": 8}
    assert brief["diagnostics"]["rustEd2kOffers"]["observedEntriesSent"] == 400
    assert brief["diagnostics"]["rustEd2kOffers"]["latestBatch"]["nextCursor"] == 400
    assert brief["diagnostics"]["antiFlood"]["udpTrackerDrops"]["bucketCounts"] == {
        "search_req": 1,
        "publish_source_req": 1,
    }
    assert "recentEvents" not in brief["diagnostics"]["antiFlood"]
    assert "recent" not in brief["diagnostics"]["antiFlood"]["udpTrackerDrops"]
    assert brief["trend"]["rustEd2kPending"]["remainingEtaMinutes"] == 440.0
    assert "latestRecord" not in brief
    assert "files" not in brief["diagnostics"]


def test_upload_demand_classification_flags_post_visibility_scheduler_gap() -> None:
    control = _load_rust_soak_control()

    result = control.upload_demand_classification(
        {
            "ed2kConnected": True,
            "ed2kHighId": True,
            "kadConnected": True,
            "kadFirewalled": False,
            "ed2kVisibilityPercent": 100.0,
            "ed2kPendingEntries": 0,
            "waitingUploads": 8,
            "uploadSpeedKiBps": 256.0,
        },
        {"uploadSpeedKiBps": 3000.0},
        {
            "rustKiBps": 250.0,
            "mfcKiBps": 3000.0,
            "mfcWaiting": 18,
            "parityGap": True,
            "postVisibilityDemandGap": True,
        },
    )

    assert result["classification"] == "scheduler-investigation"
    assert result["reason"] == "post-visibility-demand-gap"
    assert result["rustWaiting"] == 8.0
    assert result["mfcWaiting"] == 18.0


def test_watch_once_can_append_retained_evidence(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    heartbeat = tmp_path / "watch.heartbeat.txt"

    def fake_sample(base_url: str, api_key: str) -> dict[str, object]:
        if "4732" in base_url:
            return {
                "activeUploads": 1,
                "ed2kConnected": True,
                "ed2kHighId": False,
                "kadConnected": True,
                "kadFirewalled": True,
                "sharedHashingActive": True,
                "sharedHashingCount": 10,
                "uploadSpeedKiBps": 0.5,
            }
        return {
            "activeUploads": 2,
            "ed2kConnected": True,
            "ed2kHighId": True,
            "ed2kPendingEntries": 100,
            "ed2kPublishedEntries": 20,
            "kadConnected": True,
            "kadFirewalled": False,
            "sharedHashingActive": False,
            "sharedHashingCount": 0,
            "uploadSpeedKiBps": 10.0,
            "waitingUploads": 0,
        }

    monkeypatch.setattr(control, "sample", fake_sample)
    monkeypatch.setattr(
        control,
        "upload_monitor_sample",
        lambda args: {
            "monitorAlive": True,
            "monitorStale": False,
            "latestRecord": {
                "timestamp": "2026-01-01T00:00:00+00:00",
                "parityGap": False,
                "postVisibilityDemandGap": False,
                "mfcLogStale": False,
            },
        },
    )
    monkeypatch.setattr(
        control,
        "optional_watch_diagnostics",
        lambda args: {
            "fileCount": 1,
            "aggregatePatternCounts": {"ed2k": 2},
            "aggregateJsonCounts": {
                "event": {"upload_request_outcome": 2, "anti_flood_drop": 30},
                "severity": {"info": 2, "medium": 1},
            },
            "rustEd2kOfferSummary": {
                "source": "rustDiagLog",
                "rowCount": 3,
                "observedEntriesSent": 600,
                "latestBatch": {"nextCursor": 600},
            },
            "files": [{"name": "emulebb-rust-diag-123.jsonl"}],
        },
    )
    monkeypatch.setattr(
        control,
        "optional_watch_vpn",
        lambda args: {
            "allWhitelisted": True,
            "adapterUp": True,
            "bindIpPresent": True,
            "executables": [],
        },
    )

    result = control.watch_once(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="rust",
            mfc_base_url="http://192.0.2.10:4732/api/v1",
            mfc_api_key="mfc",
            output_dir=tmp_path,
            stale_seconds=900.0,
            restart_stale_monitor=False,
            log_dir=tmp_path,
            rust_pid=None,
            rust_diag_log=None,
            mfc_upload_log=None,
            interval_seconds=300.0,
            mfc_log_stale_seconds=900.0,
            append_jsonl=True,
            watch_jsonl=jsonl,
            watch_heartbeat=heartbeat,
            diagnostics_log_dir=[],
            diagnostics_log_file=[],
            include_vpn_status=True,
        )
    )

    assert "mfc-hashing-active" in result["findings"]
    assert "rust-anti-flood-drop-observed" in result["findings"]
    assert result["recommendations"] == [
        "review-rust-anti-flood-diagnostics",
        "preserve-mfc-hashing-before-connectivity-restart",
    ]
    assert result["diagnostics"]["aggregatePatternCounts"] == {"ed2k": 2}
    assert result["vpn"]["allWhitelisted"] is True
    retained = control.latest_jsonl_record(jsonl)
    assert retained is not None
    assert retained["findings"] == result["findings"]
    assert retained["recommendations"] == result["recommendations"]
    assert retained["diagnostics"]["fileCount"] == 1
    assert retained["diagnostics"]["aggregateJsonCounts"]["event"]["anti_flood_drop"] == 30
    assert retained["diagnostics"]["rustEd2kOfferSummary"]["observedEntriesSent"] == 600
    assert retained["uploadDemand"]["classification"] == "visibility-limited"
    assert retained["uploadDemand"]["reason"] == "ed2k-publish-still-maturing"
    assert retained["vpn"]["adapterUp"] is True
    heartbeat_text = heartbeat.read_text(encoding="utf-8")
    assert "mfcHashing=10" in heartbeat_text
    assert "preserve-mfc-hashing-before-connectivity-restart" in heartbeat_text
    assert "uploadDemandClassification=visibility-limited" in heartbeat_text
    assert "vpnAllWhitelisted=True" in heartbeat_text
    assert "diagnosticsFiles=1" in heartbeat_text
    assert "rustOfferObservedEntries=600" in heartbeat_text
    assert "rustOfferLatestCursor=600" in heartbeat_text


def test_watch_once_rust_only_does_not_require_upload_monitor(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    heartbeat = tmp_path / "watch.heartbeat.txt"

    monkeypatch.setattr(
        control,
        "sample",
        lambda _base_url, _api_key: {
            "activeUploads": 0,
            "ed2kConnected": True,
            "ed2kHighId": True,
            "ed2kPendingEntries": 0,
            "ed2kPublishedEntries": 100,
            "ed2kVisibilityPercent": 100.0,
            "kadConnected": True,
            "kadFirewalled": False,
            "kadGateAllowed": True,
            "kadGateBlockReason": "",
            "sharedHashingActive": False,
            "sharedHashingCount": 0,
            "uploadSpeedKiBps": 0.0,
            "waitingUploads": 0,
        },
    )
    monkeypatch.setattr(
        control,
        "upload_monitor_sample",
        lambda _args: {
            "monitorAlive": False,
            "monitorStale": True,
            "latestRecord": None,
        },
    )
    monkeypatch.setattr(control, "restart_upload_monitor", lambda _args: pytest.fail("monitor should not restart"))
    monkeypatch.setattr(control, "optional_watch_diagnostics", lambda _args: None)
    monkeypatch.setattr(control, "optional_watch_vpn", lambda _args: None)

    result = control.watch_once(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="rust",
            mfc_base_url=None,
            mfc_api_key="mfc",
            output_dir=tmp_path,
            stale_seconds=900.0,
            monitor_required=False,
            restart_stale_monitor=True,
            log_dir=tmp_path,
            rust_pid=None,
            rust_diag_log=None,
            mfc_upload_log=None,
            interval_seconds=300.0,
            mfc_log_stale_seconds=900.0,
            append_jsonl=True,
            watch_jsonl=jsonl,
            watch_heartbeat=heartbeat,
            diagnostics_log_dir=[],
            diagnostics_log_file=[],
            include_vpn_status=False,
        )
    )

    assert result["monitor"]["monitorRequired"] is False
    assert "monitor-not-running" not in result["findings"]
    assert "monitor-stale" not in result["findings"]
    assert result["recommendations"] == ["continue-soak"]
    retained = control.latest_jsonl_record(jsonl)
    assert retained is not None
    assert retained["action"]["monitorRequired"] is False
    heartbeat_text = heartbeat.read_text(encoding="utf-8")
    assert "repair-upload-monitor" not in heartbeat_text


def test_watch_loop_retains_error_sample_and_continues(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    heartbeat = tmp_path / "watch.heartbeat.txt"
    stop_file = tmp_path / "watch.stop"
    calls = iter(
        [
            TimeoutError("timed out"),
            {
                "timestampUtc": "2026-01-01T00:00:10+00:00",
                "rust": {"ed2kConnected": True, "ed2kHighId": True, "kadConnected": True},
                "monitor": {"monitorAlive": None, "monitorStale": None, "latestRecord": None},
                "uploadDemand": {"classification": "continue-soak", "reason": "no-upload-parity-action"},
                "findings": [],
                "recommendations": ["continue-soak"],
                "action": {"monitorRestarted": False},
            },
        ]
    )

    def fake_watch_once(_args: SimpleNamespace) -> dict[str, object]:
        value = next(calls)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(control, "watch_once", fake_watch_once)
    monkeypatch.setattr(control.time, "sleep", lambda _seconds: None)

    result = control.watch_loop(
        SimpleNamespace(
            max_samples=2,
            watch_stop_file=stop_file,
            watch_jsonl=jsonl,
            watch_heartbeat=heartbeat,
            watch_interval_seconds=0.1,
        )
    )

    records = [json.loads(line) for line in jsonl.read_text(encoding="utf-8").splitlines()]
    assert result["samples"] == 2
    assert records[0]["findings"] == ["watch-sample-error"]
    assert records[0]["watchError"]["type"] == "TimeoutError"
    assert records[1]["recommendations"] == ["continue-soak"]
    assert "watch-sample-error" not in heartbeat.read_text(encoding="utf-8")


def test_watch_once_brief_report_keeps_retained_evidence_full(tmp_path: Path, monkeypatch) -> None:
    control = _load_rust_soak_control()
    jsonl = tmp_path / "watch.jsonl"
    heartbeat = tmp_path / "watch.heartbeat.txt"
    pid_file = tmp_path / "watch.pid"
    stop_file = tmp_path / "watch.stop"
    pid_file.write_text("1234\n", encoding="utf-8")

    def fake_sample(base_url: str, api_key: str) -> dict[str, object]:
        if "4732" in base_url:
            return {
                "activeUploads": 1,
                "ed2kConnected": True,
                "ed2kHighId": False,
                "kadConnected": True,
                "kadFirewalled": True,
                "sharedHashingActive": True,
                "sharedHashingCount": 12,
                "uploadSpeedKiBps": 0.5,
            }
        return {
            "activeUploads": 4,
            "ed2kConnected": True,
            "ed2kHighId": True,
            "ed2kPendingEntries": 100,
            "ed2kPublishedEntries": 20,
            "kadConnected": True,
            "kadFirewalled": False,
            "sharedHashingActive": False,
            "sharedHashingCount": 0,
            "uploadSpeedKiBps": 10.0,
            "waitingUploads": 0,
        }

    monkeypatch.setattr(control, "sample", fake_sample)
    monkeypatch.setattr(control, "pid_exists", lambda pid: True)
    monkeypatch.setattr(control, "timestamp_age_seconds", lambda timestamp: 30.0)
    monkeypatch.setattr(
        control,
        "upload_monitor_sample",
        lambda args: {
            "monitorAlive": True,
            "monitorStale": False,
            "latestAgeSeconds": 5.0,
            "latestRecord": {
                "rustKiBps": 9.0,
                "rustUploads": 4,
                "mfcKiBps": 0.5,
                "mfcWaiting": 0,
                "parityGap": False,
                "mfcLogStale": False,
            },
        },
    )
    monkeypatch.setattr(
        control,
        "optional_watch_diagnostics",
        lambda args: {
            "fileCount": 1,
            "aggregatePatternCounts": {"ed2k": 2},
            "aggregateJsonCounts": {"event": {"upload_request_outcome": 2}},
            "files": [{"name": "emulebb-rust-diag-123.jsonl", "jsonRowCount": 2}],
        },
    )
    monkeypatch.setattr(
        control,
        "optional_watch_vpn",
        lambda args: {"allWhitelisted": True, "adapterUp": True, "bindIpPresent": True},
    )

    result = control.watch_once(
        SimpleNamespace(
            base_url="http://192.0.2.10:4731/api/v1",
            api_key="rust",
            mfc_base_url="http://192.0.2.10:4732/api/v1",
            mfc_api_key="mfc",
            output_dir=tmp_path,
            stale_seconds=900.0,
            restart_stale_monitor=False,
            log_dir=tmp_path,
            rust_pid=None,
            rust_diag_log=None,
            mfc_upload_log=None,
            interval_seconds=300.0,
            mfc_log_stale_seconds=900.0,
            append_jsonl=True,
            watch_jsonl=jsonl,
            watch_heartbeat=heartbeat,
            watch_pid_file=pid_file,
            watch_stop_file=stop_file,
            report="brief",
            report_limit=12,
            diagnostics_log_dir=[],
            diagnostics_log_file=[],
            include_vpn_status=True,
        )
    )

    assert result["watch"]["alive"] is True
    assert result["watch"]["stale"] is False
    assert result["findings"] == ["mfc-ed2k-not-high-id", "mfc-hashing-active", "mfc-kad-firewalled"]
    assert result["rust"]["activeUploads"] == 4
    assert result["monitor"]["rustKiBps"] == 9.0
    assert result["diagnostics"]["jsonCounts"]["event"]["upload_request_outcome"] == 2
    assert "latestRecord" not in result
    assert "files" not in result["diagnostics"]

    retained = control.latest_jsonl_record(jsonl)
    assert retained is not None
    assert retained["diagnostics"]["files"] == [{"name": "emulebb-rust-diag-123.jsonl", "jsonRowCount": 2}]
    assert retained["mfc"]["sharedHashingCount"] == 12


def _make_profile_base(profile_base: Path) -> Path:
    config = profile_base / "config"
    config.mkdir(parents=True, exist_ok=True)
    (config / "preferences.ini").write_text("[eMule]\n", encoding="utf-8")
    return profile_base


def _write_inputs_with_mfc_profile(path: Path, profile_dir: Path) -> None:
    payload = {
        "schema": "emulebb-build-tests.live-wire-inputs.v1",
        "mfc_profile": {"profile_dir": str(profile_dir)},
        "search_terms": {
            "generic_open": ["linux"],
            "documents": ["debian"],
            "radarr_movies": ["public domain movie"],
        },
        "auto_browse": {
            "bootstrap_transfer_hashes": ["0031c9cba65c50dd2015c184b2ca2c88"],
            "direct_bootstrap_transfers": [
                {"hash": "0031c9cba65c50dd2015c184b2ca2c88", "name": "x.iso", "size": 42, "method": "direct_ed2k"}
            ],
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_resolve_mfc_start_profile_uses_live_wire_profile_dir(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    profile_base = _make_profile_base(tmp_path / "EMULE_BIN")
    inputs = tmp_path / "live-wire-inputs.local.json"
    _write_inputs_with_mfc_profile(inputs, profile_base)

    resolved, mode = control.resolve_mfc_start_profile(
        SimpleNamespace(direct_profile_dir=None, rebuild_profile_from_inputs=False, inputs=inputs)
    )

    assert resolved == profile_base.resolve()
    assert mode == "inputs-json-direct"


def test_resolve_mfc_start_profile_explicit_dir_overrides_inputs(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    explicit = _make_profile_base(tmp_path / "EXPLICIT")
    inputs_profile = _make_profile_base(tmp_path / "EMULE_BIN")
    inputs = tmp_path / "live-wire-inputs.local.json"
    _write_inputs_with_mfc_profile(inputs, inputs_profile)

    resolved, mode = control.resolve_mfc_start_profile(
        SimpleNamespace(direct_profile_dir=explicit, rebuild_profile_from_inputs=False, inputs=inputs)
    )

    assert resolved == explicit
    assert mode == "explicit-direct"


def test_resolve_mfc_start_profile_rejects_incomplete_live_wire_profile(tmp_path: Path) -> None:
    control = _load_rust_soak_control()
    profile_base = tmp_path / "EMULE_BIN"
    profile_base.mkdir(parents=True, exist_ok=True)
    inputs = tmp_path / "live-wire-inputs.local.json"
    _write_inputs_with_mfc_profile(inputs, profile_base)

    with pytest.raises(RuntimeError, match="preferences.ini"):
        control.resolve_mfc_start_profile(
            SimpleNamespace(direct_profile_dir=None, rebuild_profile_from_inputs=False, inputs=inputs)
        )
