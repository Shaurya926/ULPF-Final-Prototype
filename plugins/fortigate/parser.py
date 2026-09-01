from __future__ import annotations

import json
import re


KV_RE = re.compile(r'(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=("(?:\\.|[^"\\])*"|[^\s]+)')


def _decode(value: str) -> str:
    if value.startswith('"') and value.endswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value[1:-1]
    return value


def parse(payload: str) -> dict[str, object]:
    fields: dict[str, object] = {}
    duplicates: dict[str, list[object]] = {}
    for match in KV_RE.finditer(payload):
        key, raw_value = match.groups()
        value = _decode(raw_value)
        if key in fields:
            duplicates.setdefault(key, [fields[key]]).append(value)
        fields[key] = value

    if len(fields) < 4:
        raise ValueError("not enough FortiGate key=value fields")
    if duplicates:
        fields["_duplicate_fields"] = duplicates
    return fields
