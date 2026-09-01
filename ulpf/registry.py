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

KV_RE = re.compile(r'(?P<key>[A-Za-z_][\w.-]*)=(?P<value>"(?:[^"\\]|\\.)*"|\S+)')


def parse(payload: str) -> dict[str, object]:
    text = payload.strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    fields: dict[str, object] = {}
    for match in KV_RE.finditer(text):
        value = match.group("value")
        if value.startswith('"') and value.endswith('"'):
            try:
                value = shlex.split(value)[0]
            except (ValueError, IndexError):
                value = value[1:-1]
        fields[match.group("key")] = value
    if not fields:
        raise ValueError("no structured key=value or JSON fields detected")
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
        return {
            "id": p.id,
            "version": p.manifest["version"],
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
