from ulpf.registry import PluginRegistry

from .conftest import ROOT, read_fixture


def test_fortigate_parser_handles_quoted_values():
    registry = PluginRegistry(ROOT / "plugins")
    parsed = registry.resolve("fortigate").parser(read_fixture("allow.log"))
    assert parsed["devname"] == "FGT-EDGE-01"
    assert parsed["dstcountry"] == "United States"
    assert parsed["srcip"] == "10.0.0.5"
    assert parsed["action"] == "accept"
