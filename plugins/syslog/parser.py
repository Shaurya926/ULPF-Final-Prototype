from __future__ import annotations

import re


RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured>-|\[[^\]]*\])"
    r"(?:\s+(?P<message>.*))?$"
)
ATTR_RE = re.compile(r'([A-Za-z0-9_.-]+)="((?:\\.|[^"\\])*)"')


def parse(payload: str) -> dict[str, object]:
    match = RFC5424_RE.match(payload.strip())
    if not match:
        raise ValueError("unsupported or malformed RFC5424 syslog event")
    parsed: dict[str, object] = {key: value for key, value in match.groupdict().items() if value is not None}
    pri = int(parsed["pri"])
    if not 0 <= pri <= 191:
        raise ValueError("RFC5424 PRI must be between 0 and 191")
    parsed["facility"] = pri // 8
    parsed["severity"] = pri % 8

    structured = str(parsed.pop("structured"))
    if structured != "-":
        first_space = structured.find(" ")
        if first_space < 0:
            parsed["sd_id"] = structured[1:-1]
        else:
            parsed["sd_id"] = structured[1:first_space]
            attrs = structured[first_space + 1 : -1]
            for key, value in ATTR_RE.findall(attrs):
                parsed[key] = value.replace(r'\"', '"').replace(r"\\", "\\")
    return parsed
