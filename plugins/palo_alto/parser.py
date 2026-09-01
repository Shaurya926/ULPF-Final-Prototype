from __future__ import annotations

import csv


BASE_FIELDS = [
    "marker",
    "log_type",
    "subtype",
    "vsys",
    "src_zone",
    "dst_zone",
    "srcip",
    "dstip",
    "srcport",
    "dstport",
    "proto",
    "app",
    "action",
    "severity",
]


def parse(payload: str) -> dict[str, object]:
    try:
        timestamp, csv_payload = payload.strip().split(maxsplit=1)
    except ValueError as exc:
        raise ValueError("Palo Alto fixture must contain timestamp and CSV payload") from exc

    row = next(csv.reader([csv_payload]))
    if len(row) < len(BASE_FIELDS):
        raise ValueError(f"Palo Alto traffic record has {len(row)} fields; expected at least {len(BASE_FIELDS)}")
    if row[0] != "PAN-OS" or row[1] != "TRAFFIC":
        raise ValueError("not a supported PAN-OS TRAFFIC record")

    parsed: dict[str, object] = {"timestamp": timestamp}
    parsed.update(dict(zip(BASE_FIELDS, row[: len(BASE_FIELDS)])))
    for extra in row[len(BASE_FIELDS) :]:
        if "=" in extra:
            key, value = extra.split("=", 1)
            parsed[key] = value
        elif extra:
            parsed.setdefault("_extra_values", []).append(extra)
    return parsed
