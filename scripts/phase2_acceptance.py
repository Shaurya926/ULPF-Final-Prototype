from __future__ import annotations

import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ulpf.pipeline import CoreEngine
from ulpf.registry import PluginRegistry
from ulpf.storage import SQLiteStore


DATASETS = ROOT / "datasets"
REPORTS = ROOT / "reports"


def read_payload(relative: str) -> str:
    return (DATASETS / relative).read_text(encoding="utf-8").rstrip("\n")


def has_required(event: dict[str, Any]) -> bool:
    required_paths = [
        ("@timestamp",),
        ("event", "category"),
        ("event", "type"),
        ("event", "action"),
        ("source", "ip"),
        ("destination", "ip"),
        ("network", "transport"),
        ("observer", "vendor"),
        ("observer", "product"),
    ]
    for path in required_paths:
        cursor: Any = event
        for key in path:
            if not isinstance(cursor, dict) or key not in cursor or cursor[key] in (None, ""):
                return False
            cursor = cursor[key]
    return True


def pct(passed: int, total: int) -> float:
    return round((passed / total * 100.0) if total else 0.0, 2)


def main() -> int:
    cases = json.loads((DATASETS / "expected" / "acceptance_cases.json").read_text())
    metrics: dict[str, dict[str, list[bool]]] = defaultdict(lambda: defaultdict(list))
    details: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="ulpf-phase2-") as tmp:
        engine = CoreEngine(SQLiteStore(Path(tmp) / "acceptance.db"), PluginRegistry(ROOT / "plugins"))

        for case in cases["valid"]:
            payload = read_payload(case["path"])
            detection = engine.registry.detect(payload)
            detection_ok = detection is not None and detection.plugin_id == case["plugin_id"]
            result = engine.process(payload)
            stored = result.status == "STORED" and result.event_id is not None
            event = engine.store.get_event(result.event_id) if stored else None
            raw = engine.store.get_raw(result.raw_event_id)
            namespace = case["plugin_id"]

            required_ok = bool(event and has_required(event))
            taxonomy_ok = bool(
                event
                and event["event"]["category"] == "network"
                and event["event"]["type"] == "connection"
                and event["event"]["action"] == case["action"]
            )
            raw_ok = bool(raw and raw["payload"] == payload and event and event["raw"]["event_id"] == result.raw_event_id)
            provenance_ok = bool(
                event
                and event["provenance"]["parser_id"] == case["plugin_id"]
                and event["provenance"].get("parser_version")
                and event["provenance"].get("mapping_version")
                and event["provenance"].get("field_trace") is not None
            )
            extension_ok = True
            if case.get("extension_key"):
                extension_ok = bool(
                    event
                    and case["extension_key"] in event.get("extensions", {}).get(namespace, {})
                )

            metrics[namespace]["detection_accuracy"].append(detection_ok)
            metrics[namespace]["parse_success"].append(stored)
            metrics[namespace]["required_field_extraction"].append(required_ok)
            metrics[namespace]["taxonomy_correctness"].append(taxonomy_ok)
            metrics[namespace]["raw_retention"].append(raw_ok)
            metrics[namespace]["provenance_completeness"].append(provenance_ok)
            metrics[namespace]["unmapped_retention"].append(extension_ok)
            details.append({
                "path": case["path"],
                "plugin": namespace,
                "status": result.status,
                "detection_ok": detection_ok,
                "taxonomy_ok": taxonomy_ok,
                "raw_ok": raw_ok,
                "provenance_ok": provenance_ok,
                "unmapped_retention_ok": extension_ok,
            })

        for case in cases["malformed"]:
            payload = read_payload(case["path"])
            expected_plugin = case["expected_plugin"]
            detection = engine.registry.detect(payload)
            result = engine.process(payload)
            raw = engine.store.get_raw(result.raw_event_id)
            ok = bool(
                detection
                and detection.plugin_id == expected_plugin
                and result.status == "QUARANTINED"
                and raw
                and raw["payload"] == payload
            )
            metrics[expected_plugin]["malformed_handling"].append(ok)
            details.append({"path": case["path"], "plugin": expected_plugin, "malformed_handling_ok": ok, "reason": result.reason})

        unknown_checks: list[bool] = []
        for case in cases["unknown"]:
            payload = read_payload(case["path"])
            result = engine.process(payload)
            raw = engine.store.get_raw(result.raw_event_id)
            ok = bool(
                result.status == "QUARANTINED"
                and result.reason == "UNKNOWN_SOURCE"
                and result.plugin_id is None
                and result.detection_report
                and all(not item.matched for item in result.detection_report)
                and raw
                and raw["payload"] == payload
            )
            unknown_checks.append(ok)
            details.append({"path": case["path"], "plugin": None, "unknown_source_safety_ok": ok})

    matrix: dict[str, dict[str, float]] = {}
    metric_names = [
        "detection_accuracy",
        "parse_success",
        "required_field_extraction",
        "taxonomy_correctness",
        "malformed_handling",
        "raw_retention",
        "provenance_completeness",
        "unmapped_retention",
    ]
    for plugin in sorted(metrics):
        matrix[plugin] = {}
        for name in metric_names:
            values = metrics[plugin].get(name, [])
            matrix[plugin][name] = pct(sum(values), len(values)) if values else 0.0

    report = {
        "corpus_notice": "All Phase 2 telemetry is synthetic test data, not production telemetry.",
        "valid_events": len(cases["valid"]),
        "malformed_events": len(cases["malformed"]),
        "unknown_events": len(cases["unknown"]),
        "adapter_acceptance_matrix_percent": matrix,
        "unknown_source_safety_percent": pct(sum(unknown_checks), len(unknown_checks)),
        "details": details,
    }
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "phase2_acceptance.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    headers = ["Adapter", "Detection", "Parse", "Required fields", "Taxonomy", "Malformed", "Raw", "Provenance", "Unmapped"]
    lines = [
        "# Phase 2 Adapter Acceptance Matrix",
        "",
        "> Generated by `python scripts/phase2_acceptance.py` from the repository's synthetic corpus. These are functional corpus results, not production benchmarks.",
        "",
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] + ["---:"] * (len(headers) - 1)) + "|",
    ]
    for plugin, row in matrix.items():
        lines.append(
            "| " + " | ".join([
                plugin,
                f"{row['detection_accuracy']:.2f}%",
                f"{row['parse_success']:.2f}%",
                f"{row['required_field_extraction']:.2f}%",
                f"{row['taxonomy_correctness']:.2f}%",
                f"{row['malformed_handling']:.2f}%",
                f"{row['raw_retention']:.2f}%",
                f"{row['provenance_completeness']:.2f}%",
                f"{row['unmapped_retention']:.2f}%",
            ]) + " |"
        )
    lines += ["", f"Unknown-source safe quarantine: **{report['unknown_source_safety_percent']:.2f}%** ({len(unknown_checks)} synthetic unknown records).", ""]
    (REPORTS / "phase2_acceptance.md").write_text("\n".join(lines), encoding="utf-8")

    print(json.dumps(report, indent=2, sort_keys=True))
    all_values = [value for row in matrix.values() for value in row.values()]
    return 0 if all(value == 100.0 for value in all_values) and report["unknown_source_safety_percent"] == 100.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
