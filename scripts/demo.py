from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ulpf.pipeline import CoreEngine
from ulpf.registry import PluginRegistry
from ulpf.storage import SQLiteStore


DB = ROOT / "data" / "demo.db"
if DB.exists():
    DB.unlink()
engine = CoreEngine(SQLiteStore(DB), PluginRegistry(ROOT / "plugins"))
fixture = (ROOT / "plugins" / "fortigate" / "fixtures" / "allow.log").read_text(encoding="utf-8").rstrip("\n")

result = engine.process(fixture)
print("PROCESS RESULT")
print(json.dumps(result.model_dump(mode="json"), indent=2))
print("\nRAW -> PARSED -> NORMALIZED INSPECTION")
print(json.dumps(engine.store.get_inspection(result.event_id), indent=2))
