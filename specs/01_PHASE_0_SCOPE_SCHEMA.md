# Phase 0 — Scope, Schema & Plugin Contract

## Goal
Freeze the contracts before parallel development.

## Supported prototype sources
1. Cisco ASA
2. Fortinet FortiGate
3. Palo Alto
4. Generic Syslog
5. CEF

For each, collect sanitized fixtures: allow, deny, malformed, missing optional fields, unknown fields.

## Universal Event Schema v0.1
Use **core + extensions + raw + provenance**.

```json
{
  "event_id": "evt_...",
  "@timestamp": "2026-08-26T17:00:00Z",
  "event": {
    "category": "network",
    "type": "connection",
    "action": "ALLOW",
    "severity": "INFO",
    "outcome": "success"
  },
  "source": {"ip": "10.0.0.5", "port": 52134},
  "destination": {"ip": "8.8.8.8", "port": 443},
  "network": {"transport": "TCP", "application": "https"},
  "observer": {"vendor": "Fortinet", "product": "FortiGate"},
  "extensions": {},
  "raw": {"event_id": "raw_...", "payload": "exact original event"},
  "provenance": {
    "parser_id": "fortigate",
    "parser_version": "1.0.0",
    "mapping_version": "1.0.0"
  }
}
```

### Rules
- Never invent missing data.
- Never discard unknown source attributes.
- Vendor-only data goes to `extensions`.
- Preserve the exact original event.
- Normalize timestamps but retain source information.
- Keep universal fields stable.

## Taxonomy v0.1
Start with:
- NETWORK_CONNECTION
- FIREWALL_ALLOW
- FIREWALL_DENY
- VPN_EVENT
- AUTH_EVENT
- IDS_ALERT

Value normalization:
- accept / allow / permit → `ALLOW`
- deny / drop / reject / block → `DENY`
- 6 / tcp / TCP → `TCP`
- 17 / udp / UDP → `UDP`

## Plugin contract
Each plugin declares:
- plugin ID/version
- vendor/product
- supported format
- detection rules
- parser strategy
- field mappings
- transforms
- required/optional fields
- fixtures/tests

```text
plugins/
  fortigate/
    manifest.yaml
    detection.yaml
    mappings.yaml
    fixtures/
```

Avoid a giant vendor `if/elif` chain.

## Exit checklist
- [ ] Five sources locked
- [ ] Schema v0.1 approved
- [ ] Taxonomy approved
- [ ] Plugin contract approved
- [ ] Demo story locked
- [ ] Initial issues assigned
