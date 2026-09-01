from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ulpf.api import create_app
from ulpf.errors import ContractError, SecurityError
from ulpf.pipeline import CoreEngine
from ulpf.registry import PluginRegistry
from ulpf.security import safe_plugin_child
from ulpf.storage import SQLiteStore

ROOT = Path(__file__).resolve().parents[1]


def test_oversized_event_rejected_before_persistence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ULPF_MAX_EVENT_BYTES", "32")
    store = SQLiteStore(tmp_path / "limits.db")
    engine = CoreEngine(store, PluginRegistry(ROOT / "plugins"))
    with pytest.raises(SecurityError):
        engine.process("X" * 33)
    assert store.count_raw_events() == 0


def test_file_and_batch_limits_return_413(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ULPF_MAX_FILE_BYTES", "64")
    monkeypatch.setenv("ULPF_MAX_BATCH_BYTES", "64")
    app = create_app(str(tmp_path / "api.db"), str(ROOT / "plugins"))
    client = TestClient(app)
    assert client.post("/api/v1/ingest/file", content=b"X" * 65).status_code == 413
    response = client.post("/api/v1/ingest/batch", json={"payloads": ["X" * 40, "Y" * 40]})
    assert response.status_code == 413
    assert app.state.store.count_raw_events() == 0


def test_plugin_path_traversal_is_rejected(tmp_path: Path):
    root = tmp_path / "plugin"
    root.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("x: 1", encoding="utf-8")
    with pytest.raises(ContractError):
        safe_plugin_child(root, "../outside.yaml", max_bytes=1024)


def test_ndjson_export_and_hash_traceability(tmp_path: Path):
    app = create_app(str(tmp_path / "export.db"), str(ROOT / "plugins"))
    client = TestClient(app)
    payload = (ROOT / "datasets" / "fortigate" / "allow.log").read_text(encoding="utf-8").strip()
    result = client.post("/api/v1/ingest/paste", json={"payload": payload}).json()
    exported = client.get("/api/v1/export/ndjson")
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("application/x-ndjson")
    event = json.loads(exported.text.strip())
    assert event["event_id"] == result["event_id"]
    raw = client.get(f"/api/v1/events/{result['event_id']}/raw").json()
    assert raw["payload"] == payload
    assert raw["sha256"] == event["raw"]["sha256"]


def test_rule_based_authoring_has_evidence_and_never_auto_activates(tmp_path: Path):
    app = create_app(str(tmp_path / "draft.db"), str(ROOT / "plugins"))
    client = TestClient(app)
    payload = 'timestamp=2026-08-26T17:00:00Z srcip=10.1.2.3 dstip=8.8.8.8 dstport=443 action=allow proto=tcp'
    analysis = client.post("/api/v1/onboarding/analyze", json={"payload": payload}).json()
    assert analysis["authoring_assistance"] == {
        "mode": "RULE_BASED_OFFLINE", "ai_required": False, "auto_activation": False
    }
    assert analysis["suggested_mapping_details"]["srcip"]["confidence"] > 0
    assert "evidence" in analysis["suggested_mapping_details"]["srcip"]
    draft = client.post(
        "/api/v1/onboarding/drafts",
        json={
            "payload": payload,
            "mappings": analysis["suggested_mappings"],
            "vendor": "SyntheticVendor",
            "product": "SyntheticProduct",
            "plugin_id": "synthetic_draft",
        },
    ).json()
    assert draft["auto_activated"] is False
    assert draft["status"] == "DRAFT_REVIEW_REQUIRED"
    audit = client.get("/api/v1/audit").json()
    assert audit[0]["action"] == "PLUGIN_DRAFT_CREATED"
    assert audit[0]["details"]["auto_activated"] is False


def test_plugin_runtime_change_is_audited(tmp_path: Path):
    app = create_app(str(tmp_path / "audit.db"), str(ROOT / "plugins"))
    client = TestClient(app)
    response = client.patch("/api/v1/plugins/fortigate/state", json={"enabled": False})
    assert response.status_code == 200
    audit = client.get("/api/v1/audit").json()
    assert audit[0]["object_id"] == "fortigate"
    assert audit[0]["details"] == {"after": False, "before": True, "scope": "runtime"}


def test_onboarding_fixture_validation_is_manual_gate(tmp_path: Path):
    app = create_app(str(tmp_path / "fixtures.db"), str(ROOT / "plugins"))
    client = TestClient(app)
    payloads = [
        'timestamp=2026-08-26T17:00:00Z srcip=10.1.2.3 dstip=8.8.8.8 dstport=443 action=allow proto=tcp',
        'timestamp=2026-08-26T17:00:01Z srcip=10.1.2.4 dstip=1.1.1.1 dstport=53 action=deny proto=udp',
    ]
    analysis = client.post("/api/v1/onboarding/analyze", json={"payload": payloads[0]}).json()
    response = client.post(
        "/api/v1/onboarding/validate-fixtures",
        json={
            "payloads": payloads,
            "mappings": analysis["suggested_mappings"],
            "vendor": "SyntheticVendor",
            "product": "SyntheticProduct",
            "plugin_id": "synthetic_fixture_gate",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["fixtures"] == 2
    assert data["all_ready"] is True
    assert data["auto_activated"] is False
