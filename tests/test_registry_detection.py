from pathlib import Path

from ulpf.registry import PluginRegistry

from .conftest import ROOT, read_fixture


def test_registry_loads_fortigate():
    registry = PluginRegistry(ROOT / "plugins")
    assert "fortigate" in registry.plugins
    plugin = registry.resolve("fortigate")
    assert plugin.manifest["vendor"] == "Fortinet"
    assert plugin.manifest["version"] == "1.0.0"


def test_plugin_contract_is_valid():
    registry = PluginRegistry(ROOT / "plugins")
    errors = registry.validate_plugin_dir(ROOT / "plugins" / "fortigate")
    assert errors == []


def test_deterministic_detection():
    registry = PluginRegistry(ROOT / "plugins")
    result = registry.detect(read_fixture("allow.log"))
    assert result is not None
    assert result.plugin_id == "fortigate"
    assert result.confidence == 0.99
    assert any("date=" in item for item in result.evidence)


def test_unknown_log_not_detected():
    registry = PluginRegistry(ROOT / "plugins")
    assert registry.detect(read_fixture("malformed.log")) is None
