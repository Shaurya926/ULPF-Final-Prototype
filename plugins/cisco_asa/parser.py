from __future__ import annotations

import re


ASA_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+"
    r"%ASA-(?P<severity>[0-7])-(?P<message_id>\d+):\s+"
    r"access-list\s+(?P<acl>\S+)\s+"
    r"(?P<result>permitted|denied)\s+"
    r"(?P<proto>[A-Za-z0-9]+)\s+"
    r"(?P<src_zone>[^/\s]+)/(?P<srcip>[^\s(]+)\((?P<srcport>\d+)\)\s+"
    r"->\s+"
    r"(?P<dst_zone>[^/\s]+)/(?P<dstip>[^\s(]+)\((?P<dstport>\d+)\)"
    r"(?:\s+hit-cnt\s+(?P<hitcnt>\d+))?"
    r"(?:\s+(?P<message>.*))?$",
    re.IGNORECASE,
)


def parse(payload: str) -> dict[str, object]:
    match = ASA_RE.match(payload.strip())
    if not match:
        raise ValueError("unsupported or malformed Cisco ASA access-list event")
    return {key: value for key, value in match.groupdict().items() if value is not None}
