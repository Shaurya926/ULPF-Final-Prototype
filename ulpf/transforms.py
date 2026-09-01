from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .errors import MappingError


def normalize_action(value: Any) -> str:
    normalized = str(value).strip().lower()
    allow = {"accept", "allow", "allowed", "permit", "permitted", "pass"}
    deny = {"deny", "denied", "drop", "dropped", "reject", "rejected", "block", "blocked"}
    if normalized in allow:
        return "ALLOW"
    if normalized in deny:
        return "DENY"
    raise MappingError(f"unsupported action value: {value!r}")


def normalize_transport(value: Any) -> str:
    normalized = str(value).strip().lower()
    mapping = {
        "6": "TCP",
        "tcp": "TCP",
        "17": "UDP",
        "udp": "UDP",
        "1": "ICMP",
        "icmp": "ICMP",
        "58": "ICMPV6",
        "icmpv6": "ICMPV6",
    }
    if normalized not in mapping:
        raise MappingError(f"unsupported transport value: {value!r}")
    return mapping[normalized]


def normalize_application(value: Any) -> str:
    return str(value).strip().lower()


def normalize_severity(value: Any) -> str:
    normalized = str(value).strip().upper()
    aliases = {
        "WARN": "WARNING",
        "ERR": "ERROR",
        "CRIT": "CRITICAL",
        "EMERG": "EMERGENCY",
        "INFORMATIONAL": "INFO",
        "NOTICE": "NOTICE",
    }
    return aliases.get(normalized, normalized)


def normalize_syslog_severity(value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise MappingError(f"invalid syslog severity: {value!r}") from exc
    mapping = {
        0: "EMERGENCY",
        1: "ALERT",
        2: "CRITICAL",
        3: "ERROR",
        4: "WARNING",
        5: "NOTICE",
        6: "INFO",
        7: "DEBUG",
    }
    if number not in mapping:
        raise MappingError(f"syslog severity out of range: {number}")
    return mapping[number]


def normalize_cef_severity(value: Any) -> str:
    text = str(value).strip()
    names = {
        "unknown": "UNKNOWN",
        "low": "INFO",
        "medium": "WARNING",
        "high": "ERROR",
        "very-high": "CRITICAL",
        "very high": "CRITICAL",
    }
    if text.lower() in names:
        return names[text.lower()]
    try:
        number = int(text)
    except ValueError as exc:
        raise MappingError(f"invalid CEF severity: {value!r}") from exc
    if not 0 <= number <= 10:
        raise MappingError(f"CEF severity out of range: {number}")
    if number <= 3:
        return "INFO"
    if number <= 6:
        return "WARNING"
    if number <= 8:
        return "ERROR"
    return "CRITICAL"


def normalize_fortigate_timestamp(values: dict[str, Any]) -> str:
    date = values.get("date")
    time = values.get("time")
    tz = values.get("tz")
    if not date or not time or not tz:
        raise MappingError("FortiGate timestamp requires date, time and tz")

    tz_text = str(tz).strip()
    if tz_text.upper() == "UTC":
        tz_text = "+0000"
    if len(tz_text) == 6 and tz_text[3] == ":":
        tz_text = tz_text[:3] + tz_text[4:]

    try:
        parsed = datetime.strptime(
            f"{date} {time} {tz_text}", "%Y-%m-%d %H:%M:%S %z"
        )
    except ValueError as exc:
        raise MappingError(f"invalid FortiGate timestamp: {exc}") from exc

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


TRANSFORMS = {
    "normalize_action": normalize_action,
    "normalize_transport": normalize_transport,
    "normalize_application": normalize_application,
    "normalize_severity": normalize_severity,
    "normalize_syslog_severity": normalize_syslog_severity,
    "normalize_cef_severity": normalize_cef_severity,
    "normalize_fortigate_timestamp": normalize_fortigate_timestamp,
}
