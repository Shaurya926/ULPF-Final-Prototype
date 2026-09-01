# Universal Event Schema v0.1

The universal event uses stable core fields, vendor extensions, raw evidence and provenance.

```json
{
  "event_id": "evt_...",
  "@timestamp": "2026-08-26T17:00:00Z",
  "event": {"category": "network", "type": "connection", "action": "ALLOW", "severity": "INFO", "outcome": "success"},
  "source": {"ip": "10.0.0.5", "port": 52134},
  "destination": {"ip": "8.8.8.8", "port": 443},
  "network": {"transport": "TCP", "application": "https"},
  "observer": {"vendor": "Fortinet", "product": "FortiGate"},
  "extensions": {},
  "raw": {"event_id": "raw_...", "payload": "exact original event"},
  "provenance": {"parser_id": "fortigate", "parser_version": "1.0.0", "mapping_version": "1.0.0"}
}
```

Rules: never invent missing data; never discard unknown source attributes; preserve the exact original event; put vendor-only data in `extensions`; record parser/mapping versions; keep field-level source trace wherever mapping is performed.
