from pathlib import Path

from fastapi.testclient import TestClient

from ulpf.api import create_app

from .conftest import ROOT, read_dataset


def test_api_mixed_batch_contains_all_five_sources_with_traceability(tmp_path: Path):
    app = create_app(str(tmp_path / "phase2-api.db"), str(ROOT / "plugins"))
    client = TestClient(app)
    source_paths = [
        "fortigate/allow.log",
        "cisco_asa/allow.log",
        "palo_alto/allow.log",
        "cef/allow.log",
        "syslog/allow.log",
    ]
    payloads = [read_dataset(path) for path in source_paths]

    response = client.post("/api/v1/ingest/batch", json={"payloads": payloads})
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 5
    assert all(item["status"] == "STORED" for item in results)
    assert {item["plugin_id"] for item in results} == {"fortigate", "cisco_asa", "palo_alto", "cef", "syslog"}

    for item, payload in zip(results, payloads):
        event = client.get(f"/api/v1/events/{item['event_id']}").json()
        assert event["event"]["action"] == "ALLOW"
        raw = client.get(f"/api/v1/events/{item['event_id']}/raw").json()
        assert raw["payload"] == payload
        assert event["raw"]["event_id"] == item["raw_event_id"]
