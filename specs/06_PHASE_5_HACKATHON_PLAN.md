# Phase 5 — Hackathon Execution & Pitch

## Workstreams
### Backend
Stable pipeline, five adapters, provenance, unknown queue, metrics, export, Docker.

### Frontend
Overview, ingestion, explorer, hero inspector, parser registry, onboarding.

### QA/Research
Fixtures, expected outputs, edge cases, benchmark protocol, setup verification, claim audit.

### Pitch
1. Every vendor speaks a different log language.
2. Parser fragmentation delays security analytics.
3. ULPF creates one lossless event language.
4. Live proof with mixed vendors.
5. Plugin onboarding reduces future parser effort.
6. Raw evidence + provenance establish trust.
7. Offline deployment addresses air-gap requirement.
8. Stateless architecture gives a scale path.

## 2-minute demo
- **0–20s:** show heterogeneous raw formats.
- **20–45s:** ingest/process mixed batch.
- **45–75s:** unified explorer + cross-vendor filter.
- **75–100s:** Raw→Parsed→Normalized + provenance.
- **100–115s:** unknown-source onboarding / registry.
- **115–120s:** benchmark + offline-ready close.

## Judge Q&A
**Why not a SIEM parser?**  
ULPF is a reusable preprocessing layer that standardizes telemetry before SIEM/data-lake/ML consumption.

**Why not just ECS/OCSF?**  
Schemas are useful references/targets. ULPF is the processing framework: ingestion, detection, parsing, lossless preservation, mappings, provenance, validation, onboarding and export.

**Where is AI?**  
At the expensive human step: suggesting mappings for unknown sources. Known high-volume sources stay deterministic.

**Can it handle billions/day?**  
We demonstrate measured prototype throughput and a horizontally scalable worker architecture; production sizing depends on infrastructure/workload.

**How is it lossless?**  
Exact raw payload is retained and linked to every normalized event; unmapped attributes remain accessible.

**How do you avoid wrong parsing?**  
Detection evidence, plugin validation, fixture tests, schema validation and quarantine for unknown/ambiguous inputs.

## Required deliverables
- source code link
- README
- architecture document ≤2 pages
- demo video ≤2 minutes
- technical presentation ≤5 slides where this PS-specific evaluation rule applies
- benchmark/test report
- dataset/source notes

## Exit
Three consecutive complete demos run without manual recovery.
