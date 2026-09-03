from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

import yaml

from .errors import ContractError
from .models import DetectionAttempt, DetectionResult
from .security import SecurityLimits, safe_plugin_child


REQUIRED_MANIFEST_KEYS = {
    "id",
    "version",
    "vendor",
    "product",
    "format",
    "enabled",
    "parser",
    "detection",
    "mappings",
}

# Self-contained on purpose: a registered draft parser has no vendor-specific
# structure to lean on, so it reuses the same JSON/key=value extraction that
# onboarding.analyze_payload used to show the user its fields in the first
# place. It does not import from the ulpf package — plugin directories are
# meant to stand alone, same as the hand-written vendor parsers.
GENERIC_PARSER_SOURCE = r'''from __future__ import annotations

import json
import re
import shlex

KV_RE = re.compile(
    r'(?P<key>[A-Za-z_][\w.-]*)='
    r'(?P<value>"(?:[^"\\]|\\.)*"|\S+)'
)

ISO_TS_RE = re.compile(
    r'\b\d{4}-\d{2}-\d{2}T'
    r'\d{2}:\d{2}:\d{2}'
    r'(?:\.\d+)?'
    r'(?:Z|[+-]\d{2}:?\d{2})\b'
)

IP_RE = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)


def _parse_kv(text: str) -> dict[str, object]:
    fields: dict[str, object] = {}

    for match in KV_RE.finditer(text):
        value = match.group("value")

        if value.startswith('"') and value.endswith('"'):
            try:
                value = shlex.split(value)[0]
            except (ValueError, IndexError):
                value = value[1:-1]

        fields[match.group("key")] = value

    return fields


def parse(payload: str) -> dict[str, object]:
    text = payload.strip()

    if not text:
        raise ValueError("empty payload")

    fields: dict[str, object] = {}

    # 1. JSON object
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            fields = parsed
    except json.JSONDecodeError:
        pass

    # 2. key=value structure
    if not fields:
        fields = _parse_kv(text)

    # 3. Standalone ISO-8601 timestamp
    #
    # IMPORTANT:
    # Keep this behavior aligned with onboarding.analyze_payload().
    timestamp_match = ISO_TS_RE.search(text)

    if timestamp_match and "_detected_timestamp" not in fields:
        fields["_detected_timestamp"] = timestamp_match.group(0)

    # 4. Fallback hints for otherwise unstructured logs
    if not fields:
        ips = IP_RE.findall(text)

        fields = {
            f"_detected_ip_{index + 1}": value
            for index, value in enumerate(ips)
        }

        tokens = text.split()

        for index, token in enumerate(tokens[:12]):
            fields.setdefault(
                f"_token_{index + 1}",
                token,
            )

    if not fields:
        raise ValueError(
            "no structured fields detected"
        )

    return fields
'''

def _rule_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise ContractError("detection rule values must be strings or lists of strings")


def evaluate_detection_rules(detection: dict[str, Any], payload: str, plugin_id: str = "draft") -> dict[str, Any]:
    """Standalone rule evaluation, usable both by registered plugins (via
    PluginRegistry._evaluate_detection below) and by the onboarding "test
    against another log" step, which has no Plugin object yet — only a
    candidate rules dict a human is still editing."""
    rules = detection.get("rules", {}) if isinstance(detection, dict) else {}
    if not isinstance(rules, dict):
        raise ContractError("detection.rules must be an object")

    evidence: list[str] = []
    failures: list[str] = []

    all_contains = _rule_values(rules.get("all_contains"))
    for marker in all_contains:
        if marker in payload:
            evidence.append(f"contains:{marker}")
        else:
            failures.append(f"missing required marker:{marker}")

    any_contains = _rule_values(rules.get("any_contains"))
    if any_contains:
        hits = [marker for marker in any_contains if marker in payload]
        if hits:
            evidence.extend(f"contains_any:{marker}" for marker in hits)
        else:
            failures.append("none of any_contains markers matched")

    none_contains = _rule_values(rules.get("none_contains"))
    blocked = [marker for marker in none_contains if marker in payload]
    if blocked:
        failures.extend(f"forbidden marker present:{marker}" for marker in blocked)
    elif none_contains:
        evidence.append("none_contains:clear")

    all_regex = _rule_values(rules.get("all_regex")) + _rule_values(rules.get("regex"))
    for pattern in all_regex:
        if re.search(pattern, payload):
            evidence.append(f"regex:{pattern}")
        else:
            failures.append(f"required regex did not match:{pattern}")

    any_regex = _rule_values(rules.get("any_regex"))
    if any_regex:
        hits = [pattern for pattern in any_regex if re.search(pattern, payload)]
        if hits:
            evidence.extend(f"regex_any:{pattern}" for pattern in hits)
        else:
            failures.append("none of any_regex patterns matched")

    return {
        "plugin_id": plugin_id,
        "matched": not failures,
        "confidence": float(detection.get("confidence", 1.0)) if isinstance(detection, dict) else 1.0,
        "evidence": evidence,
        "failures": failures,
    }


@dataclass
class Plugin:
    root: Path
    manifest: dict[str, Any]
    detection: dict[str, Any]
    mappings: dict[str, Any]
    parser: Callable[[str], dict[str, Any]]

    @property
    def id(self) -> str:
        return self.manifest["id"]


class PluginRegistry:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.security_limits = SecurityLimits.from_env()
        self.plugins: dict[str, Plugin] = {}
        self._all_plugins: dict[str, Plugin] = {}
        self._runtime_enabled: dict[str, bool] = {}
        self.reload()

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        if not path.exists():
            raise ContractError(f"missing plugin file: {path}")
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ContractError(f"expected mapping in {path}")
        return data

    @staticmethod
    def _load_parser(path: Path, function_name: str) -> Callable[[str], dict[str, Any]]:
        spec = importlib.util.spec_from_file_location(f"ulpf_plugin_{path.parent.name}", path)
        if spec is None or spec.loader is None:
            raise ContractError(f"cannot load parser module {path}")
        module: ModuleType = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        function = getattr(module, function_name, None)
        if not callable(function):
            raise ContractError(f"parser function {function_name!r} not found in {path}")
        return function

    def validate_plugin_dir(self, plugin_root: Path) -> list[str]:
        errors: list[str] = []
        try:
            manifest = self._load_yaml(plugin_root / "manifest.yaml")
        except ContractError as exc:
            return [str(exc)]

        missing = REQUIRED_MANIFEST_KEYS - manifest.keys()
        if missing:
            errors.append(f"manifest missing keys: {sorted(missing)}")
            return errors

        for key in ("detection", "mappings"):
            try:
                safe_plugin_child(plugin_root, str(manifest[key]), max_bytes=self.security_limits.max_plugin_file_bytes)
            except ContractError as exc:
                errors.append(str(exc))

        parser_config = manifest.get("parser", {})
        if not isinstance(parser_config, dict):
            errors.append("parser must be an object")
        else:
            parser_file = parser_config.get("file")
            parser_function = parser_config.get("function")
            if not parser_file or not parser_function:
                errors.append("parser.file and parser.function are required")
            else:
                if not str(parser_file).endswith(".py"):
                    errors.append("parser file must be .py")
                try:
                    safe_plugin_child(plugin_root, str(parser_file), max_bytes=self.security_limits.max_plugin_file_bytes)
                except ContractError as exc:
                    errors.append(str(exc))

        fixtures = plugin_root / "fixtures"
        if not fixtures.exists() or not any(fixtures.glob("*.log")):
            errors.append("at least one fixture .log is required")
        return errors

    def reload(self) -> None:
        previous = dict(self._runtime_enabled)
        self.plugins.clear()
        self._all_plugins.clear()
        self._runtime_enabled.clear()
        if not self.root.exists():
            return
        for plugin_root in sorted(p for p in self.root.iterdir() if p.is_dir()):
            errors = self.validate_plugin_dir(plugin_root)
            if errors:
                raise ContractError(f"invalid plugin {plugin_root.name}: {'; '.join(errors)}")
            manifest = self._load_yaml(plugin_root / "manifest.yaml")
            detection_path = safe_plugin_child(plugin_root, manifest["detection"], max_bytes=self.security_limits.max_plugin_file_bytes)
            mappings_path = safe_plugin_child(plugin_root, manifest["mappings"], max_bytes=self.security_limits.max_plugin_file_bytes)
            detection = self._load_yaml(detection_path)
            mappings = self._load_yaml(mappings_path)
            parser_config = manifest["parser"]
            parser_path = safe_plugin_child(plugin_root, parser_config["file"], max_bytes=self.security_limits.max_plugin_file_bytes)
            parser = self._load_parser(parser_path, parser_config["function"])
            plugin = Plugin(plugin_root, manifest, detection, mappings, parser)
            if plugin.id in self._all_plugins:
                raise ContractError(f"duplicate plugin id: {plugin.id}")
            self._all_plugins[plugin.id] = plugin
            enabled = previous.get(plugin.id, bool(manifest.get("enabled", True)))
            self._runtime_enabled[plugin.id] = enabled
            if enabled:
                self.plugins[plugin.id] = plugin

    def set_enabled(self, plugin_id: str, enabled: bool) -> dict[str, Any]:
        if plugin_id not in self._all_plugins:
            raise ContractError(f"plugin not found: {plugin_id}")
        self._runtime_enabled[plugin_id] = enabled
        if enabled:
            self.plugins[plugin_id] = self._all_plugins[plugin_id]
        else:
            self.plugins.pop(plugin_id, None)
        return self.plugin_summary(plugin_id)

    def plugin_summary(self, plugin_id: str) -> dict[str, Any]:
        p = self._all_plugins[plugin_id]
        rules = p.detection.get("rules", {}) if isinstance(p.detection, dict) else {}
        summary_parts: list[str] = []
        if isinstance(rules, dict):
            for key in ("all_contains", "any_contains", "none_contains", "all_regex", "any_regex", "regex"):
                value = rules.get(key)
                if value:
                    count = len(value) if isinstance(value, list) else 1
                    summary_parts.append(f"{key}:{count}")
        fixture_count = len(list((p.root / "fixtures").glob("*.log")))
        
        current_version = p.manifest["version"]
        versions = []
        versions_dir = p.root / "versions"
        if versions_dir.exists():
            for version_dir in versions_dir.iterdir():
                if version_dir.is_dir() and (version_dir / "manifest.yaml").exists():
                    versions.append(version_dir.name)
        if current_version not in versions:
            versions.append(current_version)
        available_versions = self._sort_versions(versions)
        
        return {
            "id": p.id,
            "version": current_version,
            "active_version": current_version,
            "version_count": len(available_versions),
            "available_versions": available_versions,
            "vendor": p.manifest["vendor"],
            "product": p.manifest["product"],
            "format": p.manifest["format"],
            "enabled": self._runtime_enabled[p.id],
            "manifest_enabled": bool(p.manifest.get("enabled", True)),
            "detection_confidence": float(p.detection.get("confidence", 1.0)),
            "detection_summary": ", ".join(summary_parts) or "custom rules",
            "fixture_count": fixture_count,
            "contract_status": "PASS",
            "state_scope": "runtime",
        }

    def list_plugins(self) -> list[dict[str, Any]]:
        return [self.plugin_summary(plugin_id) for plugin_id in sorted(self._all_plugins)]

    def resolve(self, plugin_id: str) -> Plugin:
        if plugin_id not in self.plugins:
            raise ContractError(f"plugin not found or disabled: {plugin_id}")
        return self.plugins[plugin_id]

    def _evaluate_detection(self, plugin: Plugin, payload: str) -> DetectionAttempt:
        result = evaluate_detection_rules(plugin.detection, payload, plugin_id=plugin.id)
        return DetectionAttempt(
            plugin_id=result["plugin_id"],
            matched=result["matched"],
            confidence=result["confidence"],
            evidence=result["evidence"],
            failures=result["failures"],
        )

    def write_plugin(
        self,
        plugin_id: str,
        *,
        manifest: dict[str, Any],
        detection: dict[str, Any],
        mappings: dict[str, Any],
        fixtures: list[str],
    ) -> Path:
        """Materialize an onboarding draft as a real plugin directory — the
        same manifest/detection/mappings/parser/fixtures shape as every
        hand-written adapter in plugins/. Does not touch core code."""
        plugin_dir = self.root / plugin_id
        if plugin_dir.exists():
            raise ContractError(f"a parser directory already exists for id: {plugin_id}")
        clean_fixtures = [f for f in fixtures if f and f.strip()]
        if not clean_fixtures:
            raise ContractError("at least one fixture log is required to register a parser")

        plugin_dir.mkdir(parents=True)
        (plugin_dir / "manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
        (plugin_dir / "detection.yaml").write_text(yaml.safe_dump(detection, sort_keys=False), encoding="utf-8")
        (plugin_dir / "mappings.yaml").write_text(yaml.safe_dump(mappings, sort_keys=False), encoding="utf-8")
        (plugin_dir / "parser.py").write_text(GENERIC_PARSER_SOURCE, encoding="utf-8")
        fixtures_dir = plugin_dir / "fixtures"
        fixtures_dir.mkdir()
        for index, sample in enumerate(clean_fixtures, start=1):
            (fixtures_dir / f"sample_{index}.log").write_text(sample.rstrip("\n") + "\n", encoding="utf-8")
        return plugin_dir

    def detect_with_report(self, payload: str) -> tuple[DetectionResult | None, list[DetectionAttempt]]:
        attempts = [self._evaluate_detection(plugin, payload) for plugin in self.plugins.values()]
        matches = [attempt for attempt in attempts if attempt.matched]
        if not matches:
            return None, attempts

        winner = sorted(matches, key=lambda item: (-item.confidence, item.plugin_id))[0]
        return (
            DetectionResult(
                plugin_id=winner.plugin_id,
                confidence=winner.confidence,
                evidence=winner.evidence,
            ),
            attempts,
        )

    def detect(self, payload: str) -> DetectionResult | None:
        result, _ = self.detect_with_report(payload)
        return result

    @staticmethod
    def _parse_version(version: str) -> tuple[int, int, int] | None:
        """Parse semantic version string into tuple of integers."""
        pattern = r"^(\d+)\.(\d+)\.(\d+)$"
        match = re.match(pattern, version)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return None

    @staticmethod
    def _version_tuple_to_str(major: int, minor: int, patch: int) -> str:
        """Convert version tuple to string."""
        return f"{major}.{minor}.{patch}"

    @staticmethod
    def _sort_versions(versions: list[str]) -> list[str]:
        """Sort semantic versions numerically in descending order."""
        parsed = [(v, PluginRegistry._parse_version(v)) for v in versions]
        valid = [(v, p) for v, p in parsed if p is not None]
        if not valid:
            return sorted(versions, reverse=True)
        sorted_versions = sorted(valid, key=lambda x: x[1], reverse=True)
        return [v for v, _ in sorted_versions]

    def _copy_plugin_contents(self, src_dir: Path, dest_dir: Path) -> None:
        """Copy plugin contents (manifest, detection, mappings, parser, fixtures)."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        required_files = ["manifest.yaml", "detection.yaml", "mappings.yaml", "parser.py"]
        for file_name in required_files:
            src_file = src_dir / file_name
            if src_file.exists():
                dest_file = dest_dir / file_name
                dest_file.write_text(src_file.read_text(encoding="utf-8"), encoding="utf-8")
        
        src_fixtures = src_dir / "fixtures"
        if src_fixtures.exists():
            dest_fixtures = dest_dir / "fixtures"
            dest_fixtures.mkdir(exist_ok=True)
            for log_file in src_fixtures.glob("*.log"):
                dest_file = dest_fixtures / log_file.name
                dest_file.write_text(log_file.read_text(encoding="utf-8"), encoding="utf-8")

    def list_versions(self, plugin_id: str) -> dict[str, Any]:
        """List all versions of a plugin, sorted numerically descending."""
        plugin = self._all_plugins.get(plugin_id)
        if plugin is None:
            raise ContractError(f"plugin not found: {plugin_id}")
        
        versions_dir = plugin.root / "versions"
        versions = []
        
        if versions_dir.exists():
            for version_dir in versions_dir.iterdir():
                if version_dir.is_dir() and (version_dir / "manifest.yaml").exists():
                    versions.append(version_dir.name)
        
        current_version = plugin.manifest.get("version", "1.0.0")
        if current_version not in versions:
            versions.append(current_version)
        
        sorted_versions = self._sort_versions(versions)
        
        version_list = []
        for version in sorted_versions:
            version_list.append({
                "version": version,
                "active": version == current_version,
            })
        
        return {
            "plugin_id": plugin_id,
            "active_version": current_version,
            "versions": version_list,
        }

    def ensure_version_snapshot(self, plugin_id: str) -> None:
        """Create an immutable snapshot of the current version if not already present."""
        plugin = self._all_plugins.get(plugin_id)
        if plugin is None:
            raise ContractError(f"plugin not found: {plugin_id}")
        
        current_version = plugin.manifest.get("version", "1.0.0")
        version_snapshot_dir = plugin.root / "versions" / current_version
        
        if not version_snapshot_dir.exists():
            try:
                self._copy_plugin_contents(plugin.root, version_snapshot_dir)
            except (OSError, PermissionError) as exc:
                raise ContractError(
                    f"version management requires a writable local plugin directory: {exc}"
                ) from exc

    def create_version(
        self,
        plugin_id: str,
        bump_type: str,
        release_notes: str = "",
    ) -> dict[str, Any]:
        """Create a new version by bumping the current version."""
        if bump_type not in ("patch", "minor", "major"):
            raise ContractError(f"invalid bump_type: {bump_type}")
        
        plugin = self._all_plugins.get(plugin_id)
        if plugin is None:
            raise ContractError(f"plugin not found: {plugin_id}")
        
        current_version_str = plugin.manifest.get("version", "1.0.0")
        parsed = self._parse_version(current_version_str)
        if parsed is None:
            raise ContractError(f"invalid current version format: {current_version_str}")
        
        major, minor, patch = parsed
        
        if bump_type == "patch":
            patch += 1
        elif bump_type == "minor":
            minor += 1
            patch = 0
        elif bump_type == "major":
            major += 1
            minor = 0
            patch = 0
        
        new_version = self._version_tuple_to_str(major, minor, patch)
        
        version_snapshot_dir = plugin.root / "versions" / new_version
        if version_snapshot_dir.exists():
            raise ContractError(f"version {new_version} already exists")
        
        try:
            self.ensure_version_snapshot(plugin_id)
            self._copy_plugin_contents(plugin.root, version_snapshot_dir)
            
            manifest_path = plugin.root / "manifest.yaml"
            manifest = self._load_yaml(manifest_path)
            manifest["version"] = new_version
            manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
            
            self.reload()
            
        except (OSError, PermissionError) as exc:
            raise ContractError(
                f"version management requires a writable local plugin directory: {exc}"
            ) from exc
        
        return {
            "previous_version": current_version_str,
            "new_version": new_version,
            "bump_type": bump_type,
            "release_notes": release_notes,
        }

    def activate_version(self, plugin_id: str, version: str) -> dict[str, Any]:
        """Activate a specific version of a plugin."""
        parsed = self._parse_version(version)
        if parsed is None:
            raise ContractError(f"invalid version format: {version}")
        
        plugin = self._all_plugins.get(plugin_id)
        if plugin is None:
            raise ContractError(f"plugin not found: {plugin_id}")
        
        version_snapshot_dir = plugin.root / "versions" / version
        if not version_snapshot_dir.exists():
            raise ContractError(f"version {version} not found")
        
        current_version = plugin.manifest.get("version", "1.0.0")
        
        try:
            self._copy_plugin_contents(version_snapshot_dir, plugin.root)
            
            manifest_path = plugin.root / "manifest.yaml"
            manifest = self._load_yaml(manifest_path)
            manifest["version"] = version
            manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
            
            self.reload()
            
        except (OSError, PermissionError) as exc:
            raise ContractError(
                f"version management requires a writable local plugin directory: {exc}"
            ) from exc
        
        return {
            "before": current_version,
            "after": version,
        }

    def rollback_version(self, plugin_id: str, version: str) -> dict[str, Any]:
        """Rollback to a specific version (uses activate_version internally)."""
        plugin = self._all_plugins.get(plugin_id)
        if plugin is None:
            raise ContractError(f"plugin not found: {plugin_id}")
        
        current_version = plugin.manifest.get("version", "1.0.0")
        result = self.activate_version(plugin_id, version)
        result["rollback"] = True
        return result

    def get_version_details(self, plugin_id: str, version: str) -> dict[str, Any]:
        """Get metadata about a specific version."""
        plugin = self._all_plugins.get(plugin_id)
        if plugin is None:
            raise ContractError(f"plugin not found: {plugin_id}")
        
        parsed = self._parse_version(version)
        if parsed is None:
            raise ContractError(f"invalid version format: {version}")
        
        current_version = plugin.manifest.get("version", "1.0.0")
        
        version_snapshot_dir = plugin.root / "versions" / version
        if not version_snapshot_dir.exists() and version != current_version:
            raise ContractError(f"version {version} not found")
        
        manifest_path = (version_snapshot_dir if version_snapshot_dir.exists() else plugin.root) / "manifest.yaml"
        manifest = self._load_yaml(manifest_path)
        
        return {
            "version": version,
            "active": version == current_version,
            "vendor": manifest.get("vendor"),
            "product": manifest.get("product"),
            "format": manifest.get("format"),
        }
