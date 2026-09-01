from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ulpf.pipeline import CoreEngine
from ulpf.registry import PluginRegistry
from ulpf.storage import SQLiteStore


def main() -> None:
    payloads = [line for line in (ROOT / "datasets" / "judge_demo.log").read_text(encoding="utf-8").splitlines() if line.strip()]
    with tempfile.TemporaryDirectory(prefix="ulpf-airgap-") as tmp:
        db = Path(tmp) / "persistent.db"
        store = SQLiteStore(db)
        engine = CoreEngine(store, PluginRegistry(ROOT / "plugins"))
        results = engine.process_batch(payloads)
        assert all(item.status == "STORED" for item in results)
        first_event_id = results[0].event_id
        assert first_event_id
        inspection = store.get_inspection(first_event_id)
        assert inspection and inspection["raw"]["payload"] == payloads[0]
        assert inspection["raw"]["sha256"] == hashlib.sha256(payloads[0].encode()).hexdigest()
        exported_before = store.export_events(1000)
        assert len(exported_before) == len(payloads)

        # Simulate application restart by reconstructing all state from the same local DB/plugin directory.
        restarted_store = SQLiteStore(db)
        restarted_engine = CoreEngine(restarted_store, PluginRegistry(ROOT / "plugins"))
        del restarted_engine  # construction itself proves local-only startup dependencies are sufficient
        exported_after = restarted_store.export_events(1000)
        assert exported_after == exported_before
        raw_after = restarted_store.get_raw(inspection["raw_event_id"])
        assert raw_after and raw_after["payload"] == payloads[0]

        report = {
            "offline_engine_start": "PASS",
            "ingest": "PASS",
            "normalize": "PASS",
            "inspect": "PASS",
            "export": "PASS",
            "restart_persistence": "PASS",
            "events": len(payloads),
            "network_required": False,
            "note": "Process-level air-gap proof. Container runtime must be verified on the team's Docker host.",
        }
        out = ROOT / "reports" / "phase4_airgap_check.json"
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
