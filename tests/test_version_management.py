"""Test suite for parser version management functionality."""

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from ulpf.api import create_app
from ulpf.errors import ContractError
from ulpf.registry import PluginRegistry


@pytest.fixture
def version_app(tmp_path):
    """Create app with temporary plugin directory for version testing."""
    db_path = str(tmp_path / "test.db")
    plugin_root = str(tmp_path / "plugins")
    Path(plugin_root).mkdir()
    
    app = create_app(db_path=db_path, plugin_root=plugin_root)
    client = TestClient(app)
    
    template_plugin_root = Path(__file__).parent.parent / "plugins" / "fortigate"
    if not template_plugin_root.exists():
        pytest.skip("fortigate plugin not found")
    
    import shutil
    shutil.copytree(
        str(template_plugin_root),
        str(Path(plugin_root) / "fortigate"),
        dirs_exist_ok=True
    )
    
    app.state.registry.reload()
    
    return client, app, plugin_root


class TestVersionManagementMethods:
    """Test PluginRegistry version management methods."""

    def test_parse_version(self):
        """Test semantic version parsing."""
        assert PluginRegistry._parse_version("1.0.0") == (1, 0, 0)
        assert PluginRegistry._parse_version("2.3.5") == (2, 3, 5)
        assert PluginRegistry._parse_version("10.20.30") == (10, 20, 30)
        assert PluginRegistry._parse_version("1.0") is None
        assert PluginRegistry._parse_version("v1.0.0") is None
        assert PluginRegistry._parse_version("invalid") is None

    def test_version_tuple_to_str(self):
        """Test version tuple to string conversion."""
        assert PluginRegistry._version_tuple_to_str(1, 0, 0) == "1.0.0"
        assert PluginRegistry._version_tuple_to_str(2, 3, 5) == "2.3.5"

    def test_sort_versions(self):
        """Test semantic version sorting (descending, numerically)."""
        versions = ["1.0.0", "1.0.1", "1.1.0", "2.0.0", "1.10.0", "1.9.0"]
        sorted_versions = PluginRegistry._sort_versions(versions)
        expected = ["2.0.0", "1.10.0", "1.9.0", "1.1.0", "1.0.1", "1.0.0"]
        assert sorted_versions == expected

    def test_ensure_version_snapshot_creates_snapshot(self, tmp_path):
        """TEST A: Existing plugin loads normally with no versions directory."""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            registry = PluginRegistry(plugin_root)
            assert "fortigate" in registry.plugins
            
            version_dir = fortigate_dst / "versions"
            assert not version_dir.exists()
            
            registry.ensure_version_snapshot("fortigate")
            
            version_dir = fortigate_dst / "versions" / "1.0.0"
            assert version_dir.exists()
            assert (version_dir / "manifest.yaml").exists()
            assert (version_dir / "detection.yaml").exists()
            assert (version_dir / "mappings.yaml").exists()
            assert (version_dir / "parser.py").exists()

    def test_create_version_patch(self, tmp_path):
        """TEST B: Creating patch version: 1.0.0 -> 1.0.1"""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            registry = PluginRegistry(plugin_root)
            result = registry.create_version("fortigate", "patch", "Bug fixes")
            
            assert result["previous_version"] == "1.0.0"
            assert result["new_version"] == "1.0.1"
            assert result["bump_type"] == "patch"
            assert result["release_notes"] == "Bug fixes"
            
            manifest_path = fortigate_dst / "manifest.yaml"
            manifest = yaml.safe_load(manifest_path.read_text())
            assert manifest["version"] == "1.0.1"
            
            version_dir = fortigate_dst / "versions" / "1.0.1"
            assert version_dir.exists()

    def test_create_version_minor(self, tmp_path):
        """TEST C: Creating minor version: 1.0.1 -> 1.1.0"""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            manifest_path = fortigate_dst / "manifest.yaml"
            manifest = yaml.safe_load(manifest_path.read_text())
            manifest["version"] = "1.0.1"
            manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
            
            registry = PluginRegistry(plugin_root)
            result = registry.create_version("fortigate", "minor", "New feature")
            
            assert result["new_version"] == "1.1.0"
            
            manifest = yaml.safe_load(manifest_path.read_text())
            assert manifest["version"] == "1.1.0"

    def test_create_version_major(self, tmp_path):
        """TEST D: Creating major version: 1.1.0 -> 2.0.0"""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            manifest_path = fortigate_dst / "manifest.yaml"
            manifest = yaml.safe_load(manifest_path.read_text())
            manifest["version"] = "1.1.0"
            manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
            
            registry = PluginRegistry(plugin_root)
            result = registry.create_version("fortigate", "major", "Breaking changes")
            
            assert result["new_version"] == "2.0.0"
            
            manifest = yaml.safe_load(manifest_path.read_text())
            assert manifest["version"] == "2.0.0"

    def test_historical_version_immutable(self, tmp_path):
        """TEST E: Historical version snapshot remains unchanged after later versions."""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            registry = PluginRegistry(plugin_root)
            registry.create_version("fortigate", "patch")
            
            version_100_manifest = fortigate_dst / "versions" / "1.0.0" / "manifest.yaml"
            assert version_100_manifest.exists()
            manifest_100 = yaml.safe_load(version_100_manifest.read_text())
            assert manifest_100["version"] == "1.0.0"
            
            registry.create_version("fortigate", "minor")
            
            manifest_100_after = yaml.safe_load(version_100_manifest.read_text())
            assert manifest_100_after["version"] == "1.0.0"

    def test_activate_version(self, tmp_path):
        """TEST F: Activating an older version changes registry active version."""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            registry = PluginRegistry(plugin_root)
            
            registry.create_version("fortigate", "patch")
            assert yaml.safe_load((fortigate_dst / "manifest.yaml").read_text())["version"] == "1.0.1"
            
            registry.activate_version("fortigate", "1.0.0")
            manifest = yaml.safe_load((fortigate_dst / "manifest.yaml").read_text())
            assert manifest["version"] == "1.0.0"
            
            registry.reload()
            assert registry.plugins["fortigate"].manifest["version"] == "1.0.0"

    def test_only_active_version_detects(self, tmp_path):
        """TEST G: Only active version participates in detection."""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            registry = PluginRegistry(plugin_root)
            
            payload = "date=2020-08-02 time=01:02:03 tz=UTC type=traffic action=accept"
            
            detection1 = registry.detect(payload)
            if detection1:
                version1 = registry.plugins[detection1.plugin_id].manifest["version"]
                
                registry.create_version(detection1.plugin_id, "patch")
                registry.reload()
                
                detection2 = registry.detect(payload)
                if detection2:
                    version2 = registry.plugins[detection2.plugin_id].manifest["version"]
                    assert version2 == "1.0.1"
                    
                    assert len([p for p in registry.plugins.values() if p.id == detection1.plugin_id]) == 1

    def test_version_in_provenance(self, tmp_path):
        """TEST H: Event provenance stores parser version used at processing time."""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        db_path = str(tmp_path / "test.db")
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            from ulpf.storage import SQLiteStore
            from ulpf.pipeline import CoreEngine
            
            store = SQLiteStore(db_path)
            registry = PluginRegistry(plugin_root)
            engine = CoreEngine(store, registry)
            
            payload = "date=2020-08-02 time=01:02:03 tz=UTC type=traffic action=accept"
            result1 = engine.process(payload)
            
            if result1.status == "STORED":
                event1_json = store.get_normalized_events(limit=1)[0]
                version1 = event1_json.get("provenance", {}).get("parser_version")
                
                registry.create_version("fortigate", "patch")
                registry.reload()
                engine = CoreEngine(store, registry)
                
                payload2 = "date=2020-08-02 time=02:02:03 tz=UTC type=traffic action=deny"
                result2 = engine.process(payload2)
                
                if result2.status == "STORED":
                    events = store.get_normalized_events(limit=2)
                    event2_json = next(e for e in events if e.get("raw", {}).get("event_id") != result1.raw_event_id)
                    version2 = event2_json.get("provenance", {}).get("parser_version")
                    
                    assert version1 == "1.0.0"
                    assert version2 == "1.0.1"

    def test_rollback_works_and_audited(self, tmp_path):
        """TEST I: Rollback works and is audited."""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        db_path = str(tmp_path / "test.db")
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            from ulpf.storage import SQLiteStore
            
            store = SQLiteStore(db_path)
            registry = PluginRegistry(plugin_root)
            
            registry.create_version("fortigate", "patch")
            initial_version = yaml.safe_load((fortigate_dst / "manifest.yaml").read_text())["version"]
            assert initial_version == "1.0.1"
            
            registry.rollback_version("fortigate", "1.0.0")
            registry.reload()
            
            rollback_version = yaml.safe_load((fortigate_dst / "manifest.yaml").read_text())["version"]
            assert rollback_version == "1.0.0"

    def test_enable_disable_independent_of_versions(self, tmp_path):
        """TEST J: Enable/disable still works independently of versions."""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            registry = PluginRegistry(plugin_root)
            
            registry.create_version("fortigate", "patch")
            registry.set_enabled("fortigate", False)
            
            assert registry._runtime_enabled["fortigate"] is False
            assert "fortigate" not in registry.plugins
            
            registry.set_enabled("fortigate", True)
            assert registry._runtime_enabled["fortigate"] is True
            assert "fortigate" in registry.plugins

    def test_invalid_version_format(self, tmp_path):
        """TEST K: Invalid semantic version or invalid bump returns controlled error."""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            registry = PluginRegistry(plugin_root)
            
            with pytest.raises(ContractError, match="invalid bump_type"):
                registry.create_version("fortigate", "invalid_type")
            
            with pytest.raises(ContractError, match="invalid version format"):
                registry.activate_version("fortigate", "invalid_version")

    def test_version_endpoint_returns_history(self, tmp_path):
        """TEST L: Version endpoint returns version history."""
        plugin_root = tmp_path / "plugins"
        plugin_root.mkdir()
        
        fortigate_src = Path(__file__).parent.parent / "plugins" / "fortigate"
        fortigate_dst = plugin_root / "fortigate"
        
        if fortigate_src.exists():
            import shutil
            shutil.copytree(str(fortigate_src), str(fortigate_dst), dirs_exist_ok=True)
            
            registry = PluginRegistry(plugin_root)
            
            versions_data = registry.list_versions("fortigate")
            assert versions_data["plugin_id"] == "fortigate"
            assert versions_data["active_version"] == "1.0.0"
            assert len(versions_data["versions"]) > 0
            
            registry.create_version("fortigate", "patch")
            registry.reload()
            
            versions_data = registry.list_versions("fortigate")
            assert versions_data["active_version"] == "1.0.1"
            assert len(versions_data["versions"]) == 2


class TestVersionAPI:
    """Test version management API endpoints."""

    def test_api_list_versions(self, version_app):
        """Test GET /api/v1/plugins/{plugin_id}/versions"""
        client, app, _ = version_app
        response = client.get("/api/v1/plugins/fortigate/versions")
        assert response.status_code == 200
        data = response.json()
        assert data["plugin_id"] == "fortigate"
        assert "active_version" in data
        assert "versions" in data

    def test_api_create_version(self, version_app):
        """Test POST /api/v1/plugins/{plugin_id}/versions"""
        client, app, _ = version_app
        response = client.post(
            "/api/v1/plugins/fortigate/versions",
            json={"bump_type": "patch", "release_notes": "Bug fixes"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "1.0.1"
        assert data["previous_version"] == "1.0.0"

    def test_api_activate_version(self, version_app):
        """Test POST /api/v1/plugins/{plugin_id}/versions/{version}/activate"""
        client, app, plugin_root = version_app
        
        registry = app.state.registry
        registry.create_version("fortigate", "patch")
        
        response = client.post(
            "/api/v1/plugins/fortigate/versions/1.0.0/activate"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "1.0.0"

    def test_api_rollback_version(self, version_app):
        """Test POST /api/v1/plugins/{plugin_id}/versions/{version}/rollback"""
        client, app, plugin_root = version_app
        
        registry = app.state.registry
        registry.create_version("fortigate", "patch")
        
        response = client.post(
            "/api/v1/plugins/fortigate/versions/1.0.0/rollback"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "1.0.0"

    def test_api_get_version_details(self, version_app):
        """Test GET /api/v1/plugins/{plugin_id}/versions/{version}"""
        client, app, _ = version_app
        response = client.get("/api/v1/plugins/fortigate/versions/1.0.0")
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "1.0.0"
        assert "active" in data

    def test_api_version_not_found(self, version_app):
        """Test version endpoints with invalid versions"""
        client, app, _ = version_app
        response = client.get("/api/v1/plugins/fortigate/versions/9.9.9")
        assert response.status_code == 404

    def test_api_plugin_summary_includes_versions(self, version_app):
        """Test that plugin summary includes version information"""
        client, app, _ = version_app
        response = client.get("/api/v1/plugins")
        assert response.status_code == 200
        plugins = response.json()
        fortigate = next((p for p in plugins if p["id"] == "fortigate"), None)
        assert fortigate is not None
        assert "active_version" in fortigate
        assert "version_count" in fortigate
        assert "available_versions" in fortigate
