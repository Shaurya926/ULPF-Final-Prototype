# Phase 4 — Innovation, Scale, Security & Air-Gap

## AI-assisted parser authoring
AI is optional assistance—not the high-volume core path.

```text
Unknown samples
 ↓
Structure inference
 ↓
Suggested source fields
 ↓
Suggested universal mappings
 ↓
Human review
 ↓
Plugin draft
 ↓
Fixture validation
 ↓
Activate
```

### Guardrails
- Never auto-activate generated mappings.
- Show confidence/evidence.
- Test suggestions on fixtures.
- System must work with AI disabled.
- Local open-weight model is stretch; rule-based suggestions are acceptable for prototype.

## Scale architecture
```text
Ingress → Queue → Stateless workers → Normalized output
```

Measure on actual hardware:
- events/sec
- p50/p95 latency
- batch duration
- failure rate
- memory footprint

Say “horizontally scalable architecture”; do not claim production billion-event throughput without evidence.

## Air-gap test
With internet disconnected:
- start local containers
- ingest dataset
- normalize
- inspect
- export
- restart and verify persistence

## Prototype security
- payload/file size limits
- safe file handling
- never execute log contents
- validate plugin definitions
- safely render raw logs
- audit parser changes
- secrets via environment
- optional raw-event hash for integrity

## Interoperability
Must: normalized JSON API + NDJSON export.  
Stretch: ECS mapping, OCSF mapping, OpenSearch connector, streaming output.

## Exit
Offline demo succeeds, benchmark is reproducible, failure paths are safe, and innovation does not weaken deterministic processing.
