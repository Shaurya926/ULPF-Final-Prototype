# Phase 2 — Multi-Vendor Normalization

## Goal
Prove that different vendor languages become the same event language.

## Adapter order
FortiGate → Cisco ASA → Palo Alto → CEF → Generic Syslog.

## Test corpus
```text
datasets/
  fortigate/
  cisco_asa/
  palo_alto/
  cef/
  syslog/
  unknown/
  malformed/
  expected/
```

Use sanitized vendor examples or clearly labelled synthetic fixtures. Never present synthetic telemetry as production data.

## Cross-vendor equivalence
Create semantically equivalent events in multiple formats.

Example:
```text
Fortinet: action=accept
Cisco: result=permitted
Expected universal: event.action=ALLOW
```

This is the proof that you normalize rather than merely parse.

## Losslessness tests
For every event:
- raw before processing == raw after retrieval
- unmapped attributes remain in extensions/raw
- normalized record references exact raw ID
- parser/mapping version is recorded

## Unknown source
Unknown logs must:
1. be retained
2. receive UNKNOWN_SOURCE
3. show why no parser matched
4. enter onboarding/quarantine
5. never be silently forced through the wrong parser

## Adapter acceptance matrix
Measure:
- detection accuracy
- parse success
- required-field extraction
- taxonomy correctness
- malformed handling
- raw retention
- provenance completeness

## Exit
One mixed batch containing all five sources produces a correct unified view with traceability.
