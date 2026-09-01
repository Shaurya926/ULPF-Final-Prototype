from __future__ import annotations

import json

from ulpf.registry import PluginRegistry

from .conftest import DATASETS, ROOT, read_dataset


PLUGIN_IDS = {"fortigate", "cisco_asa", "palo_alto", "cef", "syslog"}


def _get_path(data: dict, dotted: str):
    cursor = data
    for part in dotted.split("."):
        cursor = cursor[part]
    return cursor


def test_registry_loads_all_five_adapters():
    registry = PluginRegistry(ROOT / "plugins")
    assert set(registry.plugins) == PLUGIN_IDS
    for plugin_id in PLUGIN_IDS:
        assert registry.validate_plugin_dir(ROOT / "plugins" / plugin_id) == []


def test_deterministic_detection_across_all_valid_fixtures():
    cases = json.loads((DATASETS / "expected" / "acceptance_cases.json").read_text())
    registry = PluginRegistry(ROOT / "plugins")
    for case in cases["valid"]:
        detection = registry.detect(read_dataset(case["path"]))
        assert detection is not None, case["path"]
        assert detection.plugin_id == case["plugin_id"], case["path"]


def test_cross_vendor_allow_equivalence(engine):
    spec = json.loads((DATASETS / "expected" / "equivalent_allow.json").read_text())
    normalized_events = []
    for relative in spec["sources"]:
        result = engine.process(read_dataset(relative))
        assert result.status == "STORED", relative
        normalized_events.append(engine.store.get_event(result.event_id))

    for event in normalized_events:
        for dotted, expected in spec["expected"].items():
            assert _get_path(event, dotted) == expected

    assert {event["provenance"]["parser_id"] for event in normalized_events} == PLUGIN_IDS


def test_losslessness_and_extensions_across_valid_corpus(engine):
    cases = json.loads((DATASETS / "expected" / "acceptance_cases.json").read_text())
    for case in cases["valid"]:
        payload = read_dataset(case["path"])
        result = engine.process(payload)
        assert result.status == "STORED", case["path"]
        event = engine.store.get_event(result.event_id)
        raw = engine.store.get_raw(event["raw"]["event_id"])
        assert raw["payload"] == payload
        assert raw["sha256"] == event["raw"]["sha256"]
        assert event["raw"]["event_id"] == result.raw_event_id
        assert event["provenance"]["parser_id"] == case["plugin_id"]
        assert event["provenance"]["parser_version"]
        assert event["provenance"]["mapping_version"]
        if case.get("extension_key"):
            namespace = case["plugin_id"]
            assert case["extension_key"] in event["extensions"][namespace]


def test_all_malformed_cases_fail_safely_after_correct_detection(engine):
    cases = json.loads((DATASETS / "expected" / "acceptance_cases.json").read_text())
    for case in cases["malformed"]:
        payload = read_dataset(case["path"])
        detection = engine.registry.detect(payload)
        assert detection is not None, case["path"]
        assert detection.plugin_id == case["expected_plugin"], case["path"]
        result = engine.process(payload)
        assert result.status == "QUARANTINED", case["path"]
        raw = engine.store.get_raw(result.raw_event_id)
        assert raw["payload"] == payload
        assert raw["status"] == "QUARANTINED"


def test_unknown_source_has_per_plugin_failure_report_and_is_retained(engine):
    cases = json.loads((DATASETS / "expected" / "acceptance_cases.json").read_text())
    for case in cases["unknown"]:
        payload = read_dataset(case["path"])
        result = engine.process(payload)
        assert result.status == "QUARANTINED"
        assert result.reason == "UNKNOWN_SOURCE"
        assert result.plugin_id is None
        assert result.detection_report is not None
        assert {attempt.plugin_id for attempt in result.detection_report} == PLUGIN_IDS
        assert all(not attempt.matched for attempt in result.detection_report)
        assert all(attempt.failures for attempt in result.detection_report)
        raw = engine.store.get_raw(result.raw_event_id)
        assert raw["payload"] == payload
        quarantine = next(item for item in engine.store.list_quarantine() if item["raw_event_id"] == result.raw_event_id)
        assert quarantine["reason"] == "UNKNOWN_SOURCE"
        assert quarantine["details"]["detection_report"]
