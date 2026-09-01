from pathlib import Path

from fastapi.testclient import TestClient

from ulpf.api import create_app

ROOT = Path(__file__).resolve().parent.parent


def make_client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(str(tmp_path / "phase3.db"), str(ROOT / "plugins")))


def test_phase3_ui_and_overview_are_real(tmp_path: Path):
    client = make_client(tmp_path)
    page = client.get("/")
    assert page.status_code == 200
    assert "Unified Event Explorer" in page.text
    assert "RAW" in page.text and "PARSED" in page.text and "NORMALIZED" in page.text
    assert "Parser Registry" in page.text
    assert "Unknown / Onboarding" in page.text

    mixed = client.get("/api/v1/demo/datasets/mixed").json()
    result = client.post("/api/v1/ingest/batch", json={"payloads": mixed["events"]})
    assert result.status_code == 200
    assert len(result.json()) == 10
    assert all(item["status"] == "STORED" for item in result.json())

    overview = client.get("/api/v1/overview").json()
    assert overview["total_events"] == 10
    assert overview["parsed_events"] == 10
    assert overview["unknown_failed"] == 0
    assert overview["active_plugins"] == 5
    assert overview["latest_throughput"]["batch_size"] == 10
    assert overview["latest_throughput"]["events_per_sec"] > 0
    assert "not a benchmark" in overview["throughput_label"]
    assert len(overview["vendor_distribution"]) == 5
    assert overview["action_distribution"] == {"ALLOW": 5, "DENY": 5}


def test_cross_vendor_filter_and_hero_inspector(tmp_path: Path):
    client = make_client(tmp_path)
    payloads = [
        (ROOT / "datasets" / "fortigate" / "deny.log").read_text().strip(),
        (ROOT / "datasets" / "cisco_asa" / "deny.log").read_text().strip(),
        (ROOT / "datasets" / "palo_alto" / "allow.log").read_text().strip(),
    ]
    ingested = client.post("/api/v1/ingest/batch", json={"payloads": payloads}).json()
    denials = client.get("/api/v1/events", params={"action": "DENY"}).json()
    assert len(denials) == 2
    assert {e["observer"]["vendor"] for e in denials} == {"Cisco", "Fortinet"}

    event_id = ingested[0]["event_id"]
    inspection = client.get(f"/api/v1/events/{event_id}/inspect").json()
    assert inspection["raw"]["payload"] == payloads[0]
    assert inspection["parsed"]
    assert inspection["normalized"]["event"]["action"] == "DENY"
    assert inspection["field_trace"]
    assert inspection["validation"]["status"] == "PASS"
    assert inspection["normalized"]["raw"]["event_id"] == inspection["raw_event_id"]


def test_registry_runtime_toggle_is_functional(tmp_path: Path):
    client = make_client(tmp_path)
    plugins = client.get("/api/v1/plugins").json()
    fortigate = next(p for p in plugins if p["id"] == "fortigate")
    assert fortigate["enabled"] is True
    assert fortigate["contract_status"] == "PASS"
    assert fortigate["fixture_count"] >= 1
    assert fortigate["detection_summary"]

    changed = client.patch("/api/v1/plugins/fortigate/state", json={"enabled": False}).json()
    assert changed["enabled"] is False
    assert client.get("/health").json()["plugins"] == 4

    payload = (ROOT / "datasets" / "fortigate" / "allow.log").read_text().strip()
    result = client.post("/api/v1/ingest/paste", json={"payload": payload}).json()
    assert result["status"] == "QUARANTINED"
    assert result["reason"] == "UNKNOWN_SOURCE"

    changed = client.patch("/api/v1/plugins/fortigate/state", json={"enabled": True}).json()
    assert changed["enabled"] is True
    assert client.get("/health").json()["plugins"] == 5


def test_unknown_onboarding_analysis_preview_and_draft(tmp_path: Path):
    client = make_client(tmp_path)
    payload = (ROOT / "datasets" / "unknown" / "unknown_1.log").read_text().strip()

    # First prove it fails safely through the normal engine.
    quarantined = client.post("/api/v1/ingest/paste", json={"payload": payload}).json()
    assert quarantined["status"] == "QUARANTINED"
    assert quarantined["reason"] == "UNKNOWN_SOURCE"
    assert quarantined["detection_report"]

    analysis = client.post("/api/v1/onboarding/analyze", json={"payload": payload}).json()
    assert analysis["format_hint"] == "key_value"
    assert analysis["fields"]["src"] == "10.9.9.9"
    assert analysis["fields"]["dst"] == "192.0.2.10"
    assert analysis["suggested_mappings"]["src"] == "source.ip"
    assert analysis["suggested_mappings"]["decision"] == "event.action"

    mappings = {
        "_detected_timestamp": "@timestamp",
        "src": "source.ip",
        "dst": "destination.ip",
        "decision": "event.action",
    }
    body = {
        "payload": payload,
        "mappings": mappings,
        "vendor": "MysteryVendor",
        "product": "Edge Appliance",
        "plugin_id": "mystery_appliance",
    }
    preview = client.post("/api/v1/onboarding/preview", json=body).json()
    assert preview["normalized_preview"]["source"]["ip"] == "10.9.9.9"
    assert preview["normalized_preview"]["destination"]["ip"] == "192.0.2.10"
    assert preview["validation"]["note"].startswith("Preview only")
    assert preview["validation"]["ready_for_plugin_review"] is False
    assert any("ALLOW/DENY" in warning for warning in preview["validation"]["warnings"])

    saved = client.post("/api/v1/onboarding/drafts", json=body).json()
    assert saved["status"] == "DRAFT_REVIEW_REQUIRED"
    assert saved["auto_activated"] is False
    drafts = client.get("/api/v1/onboarding/drafts").json()
    assert drafts[0]["plugin_id"] == "mystery_appliance"
