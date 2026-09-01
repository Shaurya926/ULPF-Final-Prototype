from ulpf.errors import MappingError
from ulpf.transforms import normalize_action, normalize_fortigate_timestamp, normalize_transport


def test_normalize_action():
    assert normalize_action("accept") == "ALLOW"
    assert normalize_action("permit") == "ALLOW"
    assert normalize_action("DROP") == "DENY"


def test_unknown_action_fails():
    try:
        normalize_action("maybe")
    except MappingError:
        return
    raise AssertionError("unknown action should fail")


def test_transport_normalization():
    assert normalize_transport(6) == "TCP"
    assert normalize_transport("tcp") == "TCP"
    assert normalize_transport(17) == "UDP"


def test_timestamp_to_utc():
    assert normalize_fortigate_timestamp(
        {"date": "2026-08-26", "time": "17:00:00", "tz": "+0530"}
    ) == "2026-08-26T11:30:00Z"
