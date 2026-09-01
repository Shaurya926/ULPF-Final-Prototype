from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ulpf.pipeline import CoreEngine
from ulpf.registry import PluginRegistry
from ulpf.storage import SQLiteStore


SOURCES = ["fortigate", "cisco_asa", "palo_alto", "cef", "syslog"]


def subset(event: dict) -> dict:
    return {
        "parser_id": event["provenance"]["parser_id"],
        "@timestamp": event["@timestamp"],
        "action": event["event"]["action"],
        "source": event["source"],
        "destination": event["destination"],
        "transport": event["network"].get("transport"),
        "raw_event_id": event["raw"]["event_id"],
    }


def main() -> None:
    payloads = [(ROOT / "datasets" / source / "allow.log").read_text(encoding="utf-8").rstrip("\n") for source in SOURCES]
    with tempfile.TemporaryDirectory(prefix="ulpf-demo-") as tmp:
        engine = CoreEngine(SQLiteStore(Path(tmp) / "demo.db"), PluginRegistry(ROOT / "plugins"))
        results = engine.process_batch(payloads)
        events = [engine.store.get_event(result.event_id) for result in results if result.event_id]
        traceability = []
        for result, event, original in zip(results, events, payloads):
            raw = engine.store.get_raw(result.raw_event_id)
            traceability.append(raw is not None and raw["payload"] == original and event["raw"]["event_id"] == result.raw_event_id)

        print("ULPF Phase 2 mixed-vendor demo")
        print(json.dumps([subset(event) for event in events], indent=2))
        print(f"\nAdapters represented: {sorted({event['provenance']['parser_id'] for event in events})}")
        print(f"Unified ALLOW actions: {all(event['event']['action'] == 'ALLOW' for event in events)}")
        print(f"Exact raw traceability: {all(traceability)}")


if __name__ == "__main__":
    main()
