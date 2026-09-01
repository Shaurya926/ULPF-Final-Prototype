# Phase 2 Completion — Multi-Vendor Normalization

## Status

**COMPLETE for the defined Phase 2 prototype scope.**

## Exit condition

> One mixed batch containing all five sources produces a correct unified view with traceability.

Satisfied by `scripts/phase2_demo.py`, the API mixed-batch integration test, and the synthetic corpus acceptance runner.

## Adapters complete

- Fortinet FortiGate
- Cisco ASA
- Palo Alto PAN-OS
- CEF
- Generic RFC5424 Syslog

## Proofs implemented

### Cross-vendor equivalence
Five allow events use different source-language actions (`accept`, `permitted`, `allow`, `permit`) but normalize to the same universal `event.action = ALLOW` and common network fields.

### Losslessness
For every valid acceptance event:
- raw payload is stored before processing;
- retrieved raw payload equals the exact submitted payload;
- normalized event references the exact `raw_event_id`;
- parser and mapping versions are recorded;
- unmapped source attributes remain under `extensions.<adapter>`.

### Unknown-source safety
Unknown records:
- are retained in the raw store;
- receive `UNKNOWN_SOURCE`;
- are quarantined;
- expose a per-plugin detection report explaining failed deterministic rules;
- are never assigned a known plugin.

### Malformed safety
One deliberately malformed fixture per adapter is detected as its intended source and then safely quarantined when parsing/mapping fails. The raw payload remains retrievable.

## Automated verification

- `python -m pytest -q` → **22 passed**
- `python scripts/phase2_demo.py` → all five adapters represented, all five equivalent events normalize to `ALLOW`, exact raw traceability succeeds.
- `python scripts/phase2_acceptance.py` → current fixed corpus acceptance matrix generated in `reports/`.

## Corpus size

- 15 valid synthetic events
- 5 malformed synthetic events
- 2 unknown synthetic events

**Important:** the 100% acceptance values produced by this repository are results on this small, fixed synthetic test corpus. They are not production accuracy or scale claims.

## Architectural integrity

Phase 2 does not add a core vendor switch. New adapters remain manifest/parser/mapping/detection plugins, preserving the Phase 0 rule that source onboarding must not require rewriting the core engine.

## Deferred intentionally

No frontend explorer, Docker hardening, throughput benchmark, AI-assisted onboarding, OpenSearch/Kafka integration or final pitch packaging has been added in this phase because those belong to later roadmap phases.
