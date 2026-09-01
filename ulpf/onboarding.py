from __future__ import annotations

import json
import re
import shlex
from datetime import datetime, timezone
from typing import Any

from .errors import MappingError
from .mapper import map_event
from .transforms import normalize_action, normalize_transport

KV_RE = re.compile(r'(?P<key>[A-Za-z_][\w.-]*)=(?P<value>"(?:[^"\\]|\\.)*"|\S+)')
ISO_TS_RE = re.compile(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})\b')
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

ALLOWED_TARGETS = {
    "@timestamp",
    "event.action",
    "event.category",
    "event.type",
    "event.severity",
    "event.outcome",
    "source.ip",
    "source.port",
    "destination.ip",
    "destination.port",
    "network.transport",
    "network.application",
    "observer.vendor",
    "observer.product",
    "observer.name",
}


def _parse_kv(text: str) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for match in KV_RE.finditer(text):
        value = match.group("value")
        if value.startswith('"') and value.endswith('"'):
            try:
                value = shlex.split(value)[0]
            except (ValueError, IndexError):
                value = value[1:-1]
        output[match.group("key")] = value
    return output


def suggest_detection_rules(payload: str, fields: dict[str, Any], format_hint: str) -> dict[str, Any]:
    """A first-pass, editable guess at what should identify this format again.
    The human reviewing the draft can change these before registering — this
    just saves them from starting on a blank page."""
    text = payload.strip()
    markers: list[str] = []
    if format_hint == "key_value":
        markers = [f"{key}=" for key in fields if not key.startswith("_")][:4]
    elif format_hint == "json":
        markers = [f'"{key}"' for key in fields if not key.startswith("_")][:4]
    if not markers:
        markers = [token for token in text.split()[:8] if len(token) > 2][:3]
    return {"confidence": 0.75, "rules": {"all_contains": markers[:4]}}


def analyze_payload(payload: str) -> dict[str, Any]:
    text = payload.strip()
    if not text:
        return {"format_hint": "empty", "fields": {}, "structure_notes": ["Payload is empty."]}

    notes: list[str] = []
    fields: dict[str, Any] = {}
    format_hint = "text"

    try:
        parsed_json = json.loads(text)
        if isinstance(parsed_json, dict):
            fields = parsed_json
            format_hint = "json"
            notes.append("Valid JSON object detected.")
    except json.JSONDecodeError:
        pass

    if not fields:
        fields = _parse_kv(text)
        if fields:
            format_hint = "key_value"
            notes.append(f"Detected {len(fields)} key=value field(s).")

    timestamp_match = ISO_TS_RE.search(text)
    if timestamp_match and "_detected_timestamp" not in fields:
        fields["_detected_timestamp"] = timestamp_match.group(0)
        notes.append("Detected an ISO-8601 timestamp outside structured fields.")

    if not fields:
        ips = IP_RE.findall(text)
        fields = {f"_detected_ip_{index + 1}": value for index, value in enumerate(ips)}
        tokens = text.split()
        for index, token in enumerate(tokens[:12]):
            fields.setdefault(f"_token_{index + 1}", token)
        notes.append("No structured parser matched; exposed tokens and IP hints for onboarding.")

    suggestions: dict[str, str] = {}
    aliases = {
        "src": "source.ip",
        "srcip": "source.ip",
        "source_ip": "source.ip",
        "spt": "source.port",
        "srcport": "source.port",
        "dst": "destination.ip",
        "dstip": "destination.ip",
        "destination_ip": "destination.ip",
        "dpt": "destination.port",
        "dstport": "destination.port",
        "action": "event.action",
        "decision": "event.action",
        "result": "event.action",
        "proto": "network.transport",
        "protocol": "network.transport",
        "app": "network.application",
        "service": "network.application",
        "vendor": "observer.vendor",
        "product": "observer.product",
        "hostname": "observer.name",
        "host": "observer.name",
        "time": "@timestamp",
        "timestamp": "@timestamp",
        "_detected_timestamp": "@timestamp",
    }
    for key in fields:
        lowered = key.lower()
        if lowered in aliases:
            suggestions[key] = aliases[lowered]

    suggestion_details = {
        source: {
            "target": target,
            "confidence": 0.95 if source.lower() in {"srcip", "dstip", "srcport", "dstport", "action", "protocol", "proto"} else 0.80,
            "evidence": f"offline alias rule matched source field {source!r}",
            "authoring_mode": "RULE_BASED_OFFLINE",
        }
        for source, target in suggestions.items()
    }

    return {
        "format_hint": format_hint,
        "fields": fields,
        "field_count": len(fields),
        "suggested_mappings": suggestions,
        "suggested_mapping_details": suggestion_details,
        "suggested_detection": suggest_detection_rules(text, fields, format_hint),
        "structure_notes": notes,
        "authoring_assistance": {
            "mode": "RULE_BASED_OFFLINE",
            "ai_required": False,
            "auto_activation": False,
        },
    }


def _normalize_preview_value(target: str, value: Any) -> tuple[Any, str | None]:
    try:
        if target in {"source.port", "destination.port"}:
            return int(value), "integer"
        if target == "event.action":
            return normalize_action(value), "normalize_action"
        if target == "network.transport":
            return normalize_transport(value), "normalize_transport"
    except (ValueError, MappingError):
        return value, None
    return value, None


def preview_mapping(
    *,
    payload: str,
    mappings: dict[str, str],
    vendor: str,
    product: str,
    plugin_id: str,
) -> dict[str, Any]:
    analysis = analyze_payload(payload)
    parsed = analysis["fields"]
    mapping_config: dict[str, Any] = {
        "mapping_version": "draft",
        "extension_namespace": plugin_id or "draft",
        "defaults": {
            "event.category": "network",
            "event.type": "connection",
            "observer.vendor": vendor or "Unknown",
            "observer.product": product or "Unknown",
        },
        "fields": {},
    }
    warnings: list[str] = []

    for source, target in mappings.items():
        target = target.strip()
        if not target:
            continue
        if target not in ALLOWED_TARGETS:
            warnings.append(f"Unsupported target ignored: {target}")
            continue
        if source not in parsed:
            warnings.append(f"Source field is not present: {source}")
            continue
        value, transform_or_cast = _normalize_preview_value(target, parsed[source])
        rule: dict[str, Any] = {"target": target}
        if transform_or_cast == "integer":
            rule["cast"] = "integer"
        elif transform_or_cast:
            rule["transform"] = transform_or_cast
        mapping_config["fields"][source] = rule

    mapped, trace = map_event(parsed, mapping_config)

    # Preview intentionally does not create a UniversalEvent because onboarding may be incomplete.
    # Add a timestamp fallback solely as a preview warning, not invented normalized data.
    required_preview = ["@timestamp", "event.action"]
    missing: list[str] = []
    for target in required_preview:
        cursor: Any = mapped
        if target.startswith("@"):
            present = target in mapped
        else:
            present = True
            for part in target.split("."):
                if not isinstance(cursor, dict) or part not in cursor:
                    present = False
                    break
                cursor = cursor[part]
        if not present:
            missing.append(target)

    action_value = mapped.get("event", {}).get("action")
    if action_value is not None and action_value not in {"ALLOW", "DENY"}:
        warnings.append(f"event.action is not normalized to ALLOW/DENY: {action_value!r}")
    transport_value = mapped.get("network", {}).get("transport")
    if transport_value is not None and transport_value not in {"TCP", "UDP", "ICMP", "ICMPV6"}:
        warnings.append(f"network.transport is not normalized: {transport_value!r}")

    validation = {
        "ready_for_plugin_review": not missing and not warnings,
        "missing_recommended_fields": missing,
        "warnings": warnings,
        "note": "Preview only. Drafts are never auto-activated.",
    }

    return {
        "analysis": analysis,
        "normalized_preview": mapped,
        "field_trace": trace,
        "validation": validation,
        "draft_mapping_config": mapping_config,
    }
