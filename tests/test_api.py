from pathlib import Path

from fastapi.testclient import TestClient

from ulpf.api import create_app

from .conftest import ROOT, read_fixture


def test_api_vertical_slice(tmp_path: Path):
    app = create_app(str(tmp_path / "api.db"), str(ROOT / "plugins"))
    client = TestClient(app)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["plugins"] == 5
    assert health.json()["phase"] == 5

    response = client.post("/api/v1/ingest/paste", json={"payload": read_fixture("allow.log")})
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "STORED"

    inspect = client.get(f"/api/v1/events/{result['event_id']}/inspect")
    assert inspect.status_code == 200
    body = inspect.json()
    assert body["normalized"]["event"]["action"] == "ALLOW"
    assert body["raw"]["payload"] == read_fixture("allow.log")

    raw = client.get(f"/api/v1/events/{result['event_id']}/raw")
    assert raw.status_code == 200
    assert raw.json()["payload"] == read_fixture("allow.log")
