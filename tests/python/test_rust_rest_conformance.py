from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from emule_test_harness import rust_rest_conformance


class FakeEventStreamResponse:
    def __init__(
        self,
        lines: list[bytes],
        *,
        status: int = 200,
        content_type: str = "text/event-stream",
        headers: dict[str, str] | None = None,
    ):
        self._lines = list(lines)
        self.status = status
        self.headers = {
            "Content-Type": content_type,
            "Cache-Control": "no-cache, no-transform",
            "X-Contract-Version": "1.2.0",
            "X-Accel-Buffering": "no",
            **(headers or {}),
        }

    def __enter__(self) -> "FakeEventStreamResponse":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        return None

    def getcode(self) -> int:
        return self.status

    def readline(self) -> bytes:
        if not self._lines:
            return b""
        return self._lines.pop(0)


def test_run_response_conformance_invokes_rest_contract_budget() -> None:
    calls: list[tuple[str, str, str]] = []
    event_calls: list[tuple[str, str]] = []

    def exercise(base_url: str, api_key: str, budget: str) -> dict[str, object]:
        calls.append((base_url, api_key, budget))
        return {"ok": True, "failed_routes": []}

    def event_stream(base_url: str, api_key: str) -> dict[str, object]:
        event_calls.append((base_url, api_key))
        return {"ok": True, "operationId": "getEvents"}

    summary = rust_rest_conformance.run_response_conformance(
        "http://127.0.0.1:4711",
        "test-key",
        budget="contract-stress",
        rest_smoke_module=SimpleNamespace(exercise_rest_contract_completeness=exercise),
        event_stream_checker=event_stream,
    )

    assert summary["ok"] is True
    assert calls == [("http://127.0.0.1:4711", "test-key", "contract-stress")]
    assert event_calls == [("http://127.0.0.1:4711", "test-key")]
    assert summary["event_stream"] == {"ok": True, "operationId": "getEvents"}


def test_load_rest_smoke_module_pins_rust_openapi_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, str | None] = {}
    monkeypatch.delenv(rust_rest_conformance.OPENAPI_CONTRACT_ENV, raising=False)

    def load_script_module(_module_name: str, _filename: str) -> object:
        observed["during_load"] = rust_rest_conformance.os.environ.get(
            rust_rest_conformance.OPENAPI_CONTRACT_ENV
        )
        return SimpleNamespace()

    monkeypatch.setattr(rust_rest_conformance, "load_script_module", load_script_module)

    rust_rest_conformance.load_rest_smoke_module()

    assert observed["during_load"] == str(
        rust_rest_conformance.RUST_OPENAPI_CONTRACT_PATH
    )
    assert (
        rust_rest_conformance.OPENAPI_CONTRACT_ENV
        not in rust_rest_conformance.os.environ
    )


def test_load_rest_smoke_module_restores_existing_openapi_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, str | None] = {}
    monkeypatch.setenv(
        rust_rest_conformance.OPENAPI_CONTRACT_ENV, "operator-contract.yaml"
    )

    def load_script_module(_module_name: str, _filename: str) -> object:
        observed["during_load"] = rust_rest_conformance.os.environ.get(
            rust_rest_conformance.OPENAPI_CONTRACT_ENV
        )
        return SimpleNamespace()

    monkeypatch.setattr(rust_rest_conformance, "load_script_module", load_script_module)

    rust_rest_conformance.load_rest_smoke_module()

    assert observed["during_load"] == str(
        rust_rest_conformance.RUST_OPENAPI_CONTRACT_PATH
    )
    assert (
        rust_rest_conformance.os.environ[rust_rest_conformance.OPENAPI_CONTRACT_ENV]
        == "operator-contract.yaml"
    )


def test_rust_openapi_network_tags_are_mapped_to_rest_families() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()

    assert module.OPENAPI_TAG_FAMILIES["Network"] == "network"
    assert module.OPENAPI_TAG_FAMILIES["Nat"] == "nat"
    assert module.OPENAPI_TAG_FAMILIES["VpnGuard"] == "vpn-guard"
    assert module.OPENAPI_TAG_FAMILIES["IpFilter"] == "ip-filter"


def test_rust_openapi_live_disruptive_operations_are_unsafe() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()
    routes_by_operation = {
        route["operationId"]: route for route in module.REST_CONTRACT_ROUTES
    }

    for operation_id in {
        "refreshNat",
        "probeVpnGuard",
        "reloadSharedDirectories",
        "connectServerAny",
        "disconnectServers",
        "connectServer",
        "startKad",
        "stopKad",
        "bootstrapKad",
        "recheckKadFirewall",
        "deleteSearches",
        "reloadIpFilter",
        "clearLogs",
        "replaceSharedDirectories",
    }:
        assert routes_by_operation[operation_id]["safe"] is False
        assert routes_by_operation[operation_id]["safety"] == "unsafe"


def test_rust_openapi_transfer_schema_includes_delivery_fields() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()
    transfer_properties = module.load_openapi_document()["components"]["schemas"][
        "Transfer"
    ]["properties"]

    assert transfer_properties["deliveredPath"]["type"] == ["string", "null"]
    assert transfer_properties["inIncoming"] == {"type": "boolean"}


def test_rust_openapi_diagnostics_documents_transfer_event_runtime_metrics() -> None:
    module = rust_rest_conformance.load_rest_smoke_module()
    schemas = module.load_openapi_document()["components"]["schemas"]

    assert "transferEvents" in schemas["RuntimeDiagnostics"]["required"]
    assert schemas["RuntimeDiagnostics"]["properties"]["transferEvents"] == {
        "$ref": "#/components/schemas/TransferEventRuntimeDiagnostics"
    }
    assert schemas["TransferEventRuntimeDiagnostics"]["required"] == [
        "enabled",
        "stream",
        "channelCapacity",
        "queuedEventCount",
        "subscriberCount",
        "latestEventId",
        "nextEventId",
        "resumeBehavior",
    ]
    assert schemas["TransferEventRuntimeDiagnostics"]["properties"]["stream"][
        "enum"
    ] == ["sse"]
    assert schemas["TransferEventRuntimeDiagnostics"]["properties"]["resumeBehavior"][
        "enum"
    ] == ["reset"]
    for field_name in (
        "channelCapacity",
        "queuedEventCount",
        "subscriberCount",
        "latestEventId",
    ):
        assert (
            schemas["TransferEventRuntimeDiagnostics"]["properties"][field_name][
                "minimum"
            ]
            == 0
        )
    assert (
        schemas["TransferEventRuntimeDiagnostics"]["properties"]["nextEventId"][
            "minimum"
        ]
        == 1
    )


def test_run_response_conformance_rejects_api_root_base_url() -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        raise AssertionError("exercise should not run after base-url preflight failure")

    with pytest.raises(ValueError, match="without a path"):
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711/api/v1",
            "test-key",
            rest_smoke_module=SimpleNamespace(
                exercise_rest_contract_completeness=exercise
            ),
            event_stream_checker=lambda _base_url, _api_key: {"ok": True},
        )


def test_run_response_conformance_rejects_non_root_base_url() -> None:
    with pytest.raises(ValueError, match="without a path"):
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711/rest",
            "test-key",
            rest_smoke_module=SimpleNamespace(
                exercise_rest_contract_completeness=lambda *_args: {"ok": True}
            ),
            event_stream_checker=lambda _base_url, _api_key: {"ok": True},
        )


def test_run_response_conformance_raises_on_contract_failure() -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": False, "failed_routes": ["getApp"]}

    with pytest.raises(rust_rest_conformance.RestConformanceError) as raised:
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711",
            "test-key",
            rest_smoke_module=SimpleNamespace(
                exercise_rest_contract_completeness=exercise
            ),
            event_stream_checker=lambda _base_url, _api_key: {"ok": True},
        )

    assert raised.value.summary["failed_routes"] == ["getApp"]


def test_run_response_conformance_reports_event_stream_failure() -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": True, "failed_routes": []}

    with pytest.raises(rust_rest_conformance.RestConformanceError) as raised:
        rust_rest_conformance.run_response_conformance(
            "http://127.0.0.1:4711",
            "test-key",
            rest_smoke_module=SimpleNamespace(
                exercise_rest_contract_completeness=exercise
            ),
            event_stream_checker=lambda _base_url, _api_key: {
                "ok": False,
                "reason": "missing reset",
            },
        )

    assert raised.value.summary["ok"] is False
    assert raised.value.summary["failed_routes"] == ["getEvents"]
    assert raised.value.summary["event_stream"] == {
        "ok": False,
        "reason": "missing reset",
    }


def write_transfer_event_openapi(path: Path) -> Path:
    path.write_text(
        """
openapi: 3.1.0
components:
  schemas:
    TransferEvent:
      oneOf:
        - $ref: "#/components/schemas/TransferSyncResetEvent"
    TransferSyncResetEvent:
      type: object
      additionalProperties: false
      required: [id, type, reason]
      properties:
        id: { type: integer, minimum: 1 }
        type:
          type: string
          enum: [sync.reset]
        reason:
          type: string
          enum: [last-event-id]
        lastEventId: { type: string }
""",
        encoding="utf-8",
    )
    return path


def test_run_event_stream_conformance_reads_resume_reset_frame(tmp_path: Path) -> None:
    requests = []
    openapi_yaml = write_transfer_event_openapi(tmp_path / "REST-API-OPENAPI.yaml")

    def opener(request, *, timeout: float):
        requests.append((request, timeout))
        return FakeEventStreamResponse(
            [
                b"event: sync.reset\n",
                b"id: 42\n",
                b'data: {"id":42,"type":"sync.reset","reason":"last-event-id","lastEventId":"1"}\n',
                b"\n",
            ]
        )

    summary = rust_rest_conformance.run_event_stream_conformance(
        "http://127.0.0.1:4711/",
        "test-key",
        timeout_seconds=2.0,
        opener=opener,
        openapi_path=openapi_yaml,
    )

    assert summary == {
        "ok": True,
        "operationId": "getEvents",
        "path": "/api/v1/events",
        "status": 200,
        "contentType": "text/event-stream",
        "responseHeaders": {
            "Cache-Control": "no-cache, no-transform",
            "X-Contract-Version": "1.2.0",
            "X-Accel-Buffering": "no",
        },
        "payloadSchema": "TransferEvent",
    }
    request, timeout = requests[0]
    assert request.full_url == "http://127.0.0.1:4711/api/v1/events"
    assert request.headers["Accept"] == "text/event-stream"
    assert request.headers["Last-event-id"] == "1"
    assert request.headers["X-api-key"] == "test-key"
    assert timeout == 2.0


def test_run_event_stream_conformance_rejects_api_root_base_url() -> None:
    def opener(_request, *, timeout: float):
        raise AssertionError(
            "event stream opener should not run after base-url preflight failure"
        )

    with pytest.raises(ValueError, match="without a path"):
        rust_rest_conformance.run_event_stream_conformance(
            "http://127.0.0.1:4711/api/v1/",
            "test-key",
            timeout_seconds=2.0,
            opener=opener,
        )


def test_run_event_stream_conformance_fails_without_stream_headers(
    tmp_path: Path,
) -> None:
    openapi_yaml = write_transfer_event_openapi(tmp_path / "REST-API-OPENAPI.yaml")

    def opener(_request, *, timeout: float):
        assert timeout == 2.0
        return FakeEventStreamResponse(
            [
                b"event: sync.reset\n",
                b"id: 42\n",
                b'data: {"id":42,"type":"sync.reset","reason":"last-event-id","lastEventId":"1"}\n',
                b"\n",
            ],
            headers={
                "Cache-Control": "",
                "X-Contract-Version": "",
                "X-Accel-Buffering": "",
            },
        )

    summary = rust_rest_conformance.run_event_stream_conformance(
        "http://127.0.0.1:4711/",
        "test-key",
        timeout_seconds=2.0,
        opener=opener,
        openapi_path=openapi_yaml,
    )

    assert summary["ok"] is False
    assert summary["missingResponseHeaders"] == [
        "Cache-Control",
        "X-Contract-Version",
        "X-Accel-Buffering",
    ]


def test_run_event_stream_conformance_fails_on_schema_invalid_payload(
    tmp_path: Path,
) -> None:
    openapi_yaml = write_transfer_event_openapi(tmp_path / "REST-API-OPENAPI.yaml")

    def opener(_request, *, timeout: float):
        assert timeout == 2.0
        return FakeEventStreamResponse(
            [
                b"event: sync.reset\n",
                b"id: 42\n",
                b'data: {"id":42,"type":"sync.reset","lastEventId":"1"}\n',
                b"\n",
            ]
        )

    summary = rust_rest_conformance.run_event_stream_conformance(
        "http://127.0.0.1:4711/",
        "test-key",
        timeout_seconds=2.0,
        opener=opener,
        openapi_path=openapi_yaml,
    )

    assert summary["ok"] is False
    assert "payloadSchemaError" in summary
    assert "not valid under any of the given schemas" in str(
        summary["payloadSchemaError"]
    )


def test_run_cli_writes_failed_conformance_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    def exercise(_base_url: str, _api_key: str, _budget: str) -> dict[str, object]:
        return {"ok": False, "failed_routes": ["getApp"]}

    monkeypatch.setattr(
        rust_rest_conformance,
        "load_rest_smoke_module",
        lambda: SimpleNamespace(exercise_rest_contract_completeness=exercise),
    )
    monkeypatch.setattr(
        rust_rest_conformance,
        "run_event_stream_conformance",
        lambda _base_url, _api_key: {"ok": True},
    )
    output_path = tmp_path / "conformance.json"

    exit_code = rust_rest_conformance.run_cli(
        [
            "--base-url",
            "http://127.0.0.1:4711",
            "--api-key",
            "test-key",
            "--json-output",
            str(output_path),
        ]
    )

    assert exit_code == 1
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "event_stream": {"ok": True},
        "failed_routes": ["getApp"],
        "ok": False,
    }


def test_run_cli_reports_api_root_base_url_as_preflight_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = rust_rest_conformance.run_cli(
        [
            "--base-url",
            "http://127.0.0.1:4711/api/v1",
            "--api-key",
            "test-key",
        ]
    )

    assert exit_code == 2
    assert "preflight failed" in capsys.readouterr().out
