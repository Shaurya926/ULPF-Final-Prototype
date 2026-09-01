from __future__ import annotations

import re


KEY_RE = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9]*)=")


def _parse_extensions(text: str) -> dict[str, str]:
    matches = list(KEY_RE.finditer(text))
    values: dict[str, str] = {}
    for index, match in enumerate(matches):
        key = match.group(1)
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        value = text[start:end].strip()
        value = value.replace(r"\=", "=").replace(r"\\", "\\")
        values[key] = value
    return values


def parse(payload: str) -> dict[str, object]:
    marker = payload.find("CEF:")
    if marker < 0:
        raise ValueError("CEF header not found")
    timestamp = payload[:marker].strip()
    cef_payload = payload[marker + 4 :]
    parts = cef_payload.split("|", 7)
    if len(parts) != 8:
        raise ValueError("malformed CEF header")
    version, vendor, product, device_version, signature_id, name, severity, extension = parts
    if not version.isdigit():
        raise ValueError("invalid CEF version")
    parsed: dict[str, object] = {
        "timestamp": timestamp,
        "cef_version": version,
        "device_vendor": vendor,
        "device_product": product,
        "device_version": device_version,
        "signature_id": signature_id,
        "name": name,
        "severity": severity,
    }
    parsed.update(_parse_extensions(extension))
    return parsed
