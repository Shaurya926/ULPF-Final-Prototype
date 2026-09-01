from .conftest import read_fixture


def test_allow_fixture_end_to_end(engine):
    raw_payload = read_fixture("allow.log")
    result = engine.process(raw_payload)

    assert result.status == "STORED"
    assert result.plugin_id == "fortigate"
    assert result.event_id

    event = engine.store.get_event(result.event_id)
    assert event is not None
    assert event["@timestamp"] == "2026-08-26T11:30:00Z"
    assert event["event"]["action"] == "ALLOW"
    assert event["source"]["ip"] == "10.0.0.5"
    assert event["destination"]["port"] == 443
    assert event["network"]["transport"] == "TCP"
    assert event["observer"]["vendor"] == "Fortinet"
    assert event["provenance"]["parser_version"] == "1.0.0"
    assert event["provenance"]["mapping_version"] == "1.0.0"

    raw = engine.store.get_raw(event["raw"]["event_id"])
    assert raw is not None
    assert raw["payload"] == raw_payload
    assert raw["sha256"] == event["raw"]["sha256"]

    inspection = engine.store.get_inspection(result.event_id)
    assert inspection["raw"]["payload"] == raw_payload
    assert inspection["parsed"]["srcip"] == "10.0.0.5"
    assert inspection["normalized"]["event"]["action"] == "ALLOW"


def test_deny_fixture_normalizes_action(engine):
    result = engine.process(read_fixture("deny.log"))
    assert result.status == "STORED"
    event = engine.store.get_event(result.event_id)
    assert event["event"]["action"] == "DENY"


def test_missing_optional_fields_still_pass(engine):
    result = engine.process(read_fixture("missing_optional.log"))
    assert result.status == "STORED"
    event = engine.store.get_event(result.event_id)
    assert "port" not in event.get("source", {})
    assert "application" not in event.get("network", {})


def test_unknown_fields_are_preserved_in_extensions(engine):
    result = engine.process(read_fixture("unknown_fields.log"))
    assert result.status == "STORED"
    event = engine.store.get_event(result.event_id)
    ext = event["extensions"]["fortigate"]
    assert ext["custom_alpha"] == "preserve-me"
    assert ext["custom_beta"] == "42"
    assert ext["logid"] == "0000000013"


def test_malformed_event_is_quarantined(engine):
    raw_payload = read_fixture("malformed.log")
    result = engine.process(raw_payload)
    assert result.status == "QUARANTINED"
    assert result.reason == "UNKNOWN_SOURCE"
    raw = engine.store.get_raw(result.raw_event_id)
    assert raw["payload"] == raw_payload
    assert raw["status"] == "QUARANTINED"
    quarantine = engine.store.list_quarantine()
    assert quarantine[0]["reason"] == "UNKNOWN_SOURCE"
