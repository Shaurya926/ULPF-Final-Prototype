# Phase 1 — Core Engine

## Goal
Make one source travel correctly through the entire system before adding vendors.

```text
Input
 ↓
Ingestion
 ↓
Raw Store
 ↓
Detection
 ↓
Parser Registry
 ↓
Parser
 ↓
Mapping
 ↓
Value Normalization
 ↓
Validation
 ↓
Normalized Store/API
```

## Build order
### 1. Ingestion
Support file upload, paste, batch upload and optionally HTTP ingestion. Assign every event a `raw_event_id` and processing status.

### 2. Raw preservation
Store the exact payload before transformation.

### 3. Detection
Return plugin ID, confidence and detection evidence. Known-source detection should be deterministic.

### 4. Registry
Load plugins dynamically; list, validate, version, enable/disable and resolve adapters.

### 5. Parsing
Parser converts raw payload into source-shaped attributes.

### 6. Mapping
Example:
```yaml
srcip:
  target: source.ip
dstip:
  target: destination.ip
dstport:
  target: destination.port
  cast: integer
action:
  target: event.action
  transform: normalize_action
```

### 7. Validation
Validate IPs, ports, timestamps, enums, provenance and raw references. Failed events go to a quarantine path with a reason.

### 8. Provenance
Advanced field trace:
```json
{
  "source.ip": {"source_field": "srcip"},
  "event.action": {"source_field": "action", "transform": "normalize_action"}
}
```

## First vertical slice
Use **FortiGate only** until:
1. upload works
2. raw is saved
3. source is detected
4. event is parsed
5. fields are mapped
6. values normalized
7. schema validated
8. normalized API returns event
9. raw event can be retrieved from it

## Tests
- transform unit tests
- detection tests
- parser tests
- plugin contract tests
- raw→normalized integration test
- regression fixtures

## Exit
One FortiGate fixture passes a fully automated end-to-end test and can be inspected through UI/API.
