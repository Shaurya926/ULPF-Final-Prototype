# ULPF Architecture — Final Hackathon Build

## Mission
ULPF is a vendor-agnostic, lossless preprocessing layer for perimeter-device logs. It does not replace a SIEM. It prepares heterogeneous telemetry for SIEMs, data lakes, search systems and analytics by converting many vendor formats into one stable universal event schema while preserving exact raw evidence.

**Promise:** one schema, any supported perimeter device, zero forensic data loss.

## Pipeline

```text
Heterogeneous logs → Ingestion and size checks → Raw store + SHA-256 → Deterministic detection → Plugin registry → Source parser → YAML mapping and value normalization → Schema validation → Normalized API / NDJSON export / explorer
```

The pipeline is raw-first: the original payload is stored before parsing. Every normalized record keeps a raw event ID, parser ID/version, mapping version and field-level trace. If an event cannot be safely detected or validated, it is retained in quarantine instead of being forced through a wrong parser.

## Components

- **Ingestion:** paste, file body, batch and demo dataset ingestion through API/UI.
- **Storage:** SQLite prototype store with raw events, normalized events, quarantine, metrics, onboarding drafts and audit trail.
- **Detection:** deterministic plugin-owned rules return confidence and evidence. Unknown events store per-plugin failure evidence.
- **Plugin registry:** dynamically loads versioned plugin manifests, detection rules, mappings and parser modules. Runtime enable/disable is audited.
- **Mapping and normalization:** maps source-shaped output to the universal schema and records source-field provenance.
- **Validation:** verifies required schema fields, IPs, ports, raw references, parser provenance and known enum values.
- **UX/API:** overview, ingestion, unified explorer, RAW → PARSED → NORMALIZED inspector, registry and unknown-source onboarding preview.
- **Exports:** normalized JSON API and NDJSON export for SIEM/data-lake ingestion.

## Supported adapters

The final prototype supports Fortinet FortiGate, Cisco ASA, Palo Alto PAN-OS, CEF and Generic RFC5424 Syslog through independent plugins. This proves normalization rather than simple parsing: vendor-specific allow/permit/accept values become the same `event.action = ALLOW`.

## Unknown-source onboarding

```text
Unknown samples → structure inference → suggested fields/mappings → preview → fixture validation → plugin draft → human review → activation
```

The prototype uses offline rule-based assistance. No internet or AI service is required. Drafts are never auto-activated.

## Security, air-gap and scale

The core demo works without internet. Hardening includes event/file/batch limits, pre-persistence rejection for oversized payloads, plugin path validation, escaped raw rendering, environment-based configuration, audit logging and raw SHA-256 integrity checks. Docker and Compose packaging are included with a persistent volume.

The prototype engine is single-process for hackathon reliability. The target architecture is horizontally scalable:

```text
Ingress → Queue → Stateless workers → Normalized output
```

The project reports measured prototype throughput only; it does not claim production-scale throughput without deployment evidence.
