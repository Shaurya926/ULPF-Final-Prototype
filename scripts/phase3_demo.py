#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent

# Allow direct invocation: python scripts/phase3_demo.py
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ulpf.api import create_app  # noqa: E402


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ulpf-phase3-") as temp_dir:
        app = create_app(str(Path(temp_dir) / "demo.db"), str(ROOT / "plugins"))
        client = TestClient(app)

        dataset = client.get("/api/v1/demo/datasets/mixed").json()
        processed = client.post("/api/v1/ingest/batch", json={"payloads": dataset["events"]}).json()
        denials = client.get("/api/v1/events", params={"action": "DENY"}).json()
        all_events = client.get("/api/v1/events").json()

        fortigate_allow = next(
            event for event in all_events
            if event["observer"]["vendor"] == "Fortinet" and event["event"]["action"] == "ALLOW"
        )
        cisco_allow = next(
            event for event in all_events
            if event["observer"]["vendor"] == "Cisco" and event["event"]["action"] == "ALLOW"
        )
        inspection = client.get(f"/api/v1/events/{fortigate_allow['event_id']}/inspect").json()

        unknown_payload = (ROOT / "datasets" / "unknown" / "unknown_1.log").read_text(encoding="utf-8").strip()
        unknown_result = client.post("/api/v1/ingest/paste", json={"payload": unknown_payload}).json()
        analysis = client.post("/api/v1/onboarding/analyze", json={"payload": unknown_payload}).json()
        onboarding_body = {
            "payload": unknown_payload,
            "mappings": {
                "_detected_timestamp": "@timestamp",
                "src": "source.ip",
                "dst": "destination.ip",
                "decision": "event.action",
            },
            "vendor": "MysteryVendor",
            "product": "Edge Appliance",
            "plugin_id": "mystery_appliance",
        }
        preview = client.post("/api/v1/onboarding/preview", json=onboarding_body).json()
        draft = client.post("/api/v1/onboarding/drafts", json=onboarding_body).json()
        overview = client.get("/api/v1/overview").json()

        report = {
            "dataset": {"synthetic": dataset["synthetic"], "events": len(dataset["events"])},
            "stored": sum(item["status"] == "STORED" for item in processed),
            "deny_filter_count": len(denials),
            "cross_vendor_equivalence": {
                "fortigate_action": fortigate_allow["event"]["action"],
                "cisco_action": cisco_allow["event"]["action"],
                "same_action": fortigate_allow["event"]["action"] == cisco_allow["event"]["action"],
            },
            "hero_inspector": {
                "raw_exact": inspection["raw"]["payload"] == fortigate_allow["raw"]["payload"],
                "field_trace_entries": len(inspection["field_trace"]),
                "validation": inspection["validation"]["status"],
            },
            "unknown_source": {
                "status": unknown_result["status"],
                "reason": unknown_result["reason"],
                "detection_attempts": len(unknown_result.get("detection_report") or []),
                "detected_structure": analysis["format_hint"],
            },
            "onboarding": {
                "preview_ready": preview["validation"]["ready_for_plugin_review"],
                "warnings": preview["validation"]["warnings"],
                "draft_status": draft["status"],
                "auto_activated": draft["auto_activated"],
            },
            "local_throughput_measurement": overview["latest_throughput"],
            "throughput_notice": overview["throughput_label"],
        }
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
