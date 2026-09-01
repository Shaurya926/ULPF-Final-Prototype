from __future__ import annotations

from copy import deepcopy
from typing import Any

from .errors import MappingError
from .transforms import TRANSFORMS


def _set_path(target: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cursor = target
    for part in parts[:-1]:
        cursor = cursor.setdefault(part, {})
    cursor[parts[-1]] = value


def _cast(value: Any, cast_name: str | None) -> Any:
    if cast_name is None:
        return value
    try:
        if cast_name == "integer":
            return int(value)
        if cast_name == "string":
            return str(value)
    except (TypeError, ValueError) as exc:
        raise MappingError(f"cannot cast {value!r} as {cast_name}") from exc
    raise MappingError(f"unsupported cast: {cast_name}")


def map_event(parsed: dict[str, Any], mapping_config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    output: dict[str, Any] = {}
    trace: dict[str, Any] = {}
    consumed: set[str] = set()

    for target, value in mapping_config.get("defaults", {}).items():
        _set_path(output, target, deepcopy(value))
        trace[target] = {"default": True}

    for source_key, rule in mapping_config.get("fields", {}).items():
        if not isinstance(rule, dict) or "target" not in rule:
            raise MappingError(f"invalid mapping rule for {source_key}")

        source_names = rule.get("sources") or [source_key]
        if isinstance(source_names, str):
            source_names = [source_names]
        present = {name: parsed[name] for name in source_names if name in parsed}
        required = bool(rule.get("required", False))
        if required and len(present) != len(source_names):
            missing = [name for name in source_names if name not in parsed]
            raise MappingError(f"missing required source fields: {missing}")
        if not present:
            continue

        if rule.get("transform"):
            transform_name = rule["transform"]
            transform = TRANSFORMS.get(transform_name)
            if not transform:
                raise MappingError(f"unknown transform: {transform_name}")
            value = transform(present if len(source_names) > 1 else next(iter(present.values())))
        else:
            value = next(iter(present.values()))

        value = _cast(value, rule.get("cast"))
        _set_path(output, rule["target"], value)
        consumed.update(present.keys())
        trace[rule["target"]] = {
            "source_field": source_names if len(source_names) > 1 else source_names[0],
            **({"transform": rule["transform"]} if rule.get("transform") else {}),
            **({"cast": rule["cast"]} if rule.get("cast") else {}),
        }

    namespace = mapping_config.get("extension_namespace", "source")
    extensions = {k: v for k, v in parsed.items() if k not in consumed}
    if extensions:
        output.setdefault("extensions", {})[namespace] = extensions

    return output, trace
