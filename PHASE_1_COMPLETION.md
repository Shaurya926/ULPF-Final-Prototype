# Phase 1 Completion Record

## Exit condition

**PASS** — one FortiGate fixture travels from ingestion to raw preservation, deterministic detection, dynamic parser resolution, parsing, mapping, normalization, validation, normalized storage/API, and exact raw retrieval.

## Verified behaviors

- [x] Paste ingestion
- [x] Batch ingestion
- [x] Text-file HTTP ingestion
- [x] `raw_event_id` assigned before transformation
- [x] Exact raw payload persisted
- [x] SHA-256 recorded for raw evidence
- [x] Deterministic FortiGate detection returns plugin ID, confidence and evidence
- [x] Plugin registry loads adapters dynamically
- [x] Parser returns source-shaped fields
- [x] YAML mappings generate universal fields
- [x] Action/transport/timestamp values normalize deterministically
- [x] IP, port, timestamp and schema validation enforced
- [x] Unknown/malformed source enters quarantine
- [x] Unmapped vendor fields survive in `extensions.fortigate`
- [x] Parser and mapping versions recorded
- [x] Per-field provenance trace recorded
- [x] Normalized event can retrieve exact raw event
- [x] Raw → Parsed → Normalized inspector available via API
- [x] Automated tests pass

## Verification result

`python -m pytest -q` → **15 passed**.

The standalone demo command `python scripts/demo.py` was also executed successfully against `allow.log` and produced a stored normalized event with exact raw traceability.

## Not part of Phase 1

Cisco ASA, Palo Alto, Generic Syslog and CEF adapters remain intentionally unimplemented until Phase 2. UI explorer/registry surfaces remain Phase 3. Docker/benchmarks/AI onboarding remain Phase 4.
