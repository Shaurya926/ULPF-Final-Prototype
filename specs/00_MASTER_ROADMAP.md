# ULPF — SIH 2026 Master Roadmap

**PS:** SIH26156 — Universal Log Pre-processing Framework (NTRO)  
**Immediate goal:** build an outstanding inter-college prototype without creating a throwaway architecture.

## North Star
Build a **vendor-agnostic, lossless cyber-event translation layer** for perimeter network devices.

`Heterogeneous logs → Ingest → Detect → Parse → Normalize → Validate → Preserve provenance → Export`

**Promise:** **One schema. Any supported perimeter device. Zero forensic data loss.**

The product is the preprocessing framework—not a SIEM dashboard and not an LLM-to-JSON wrapper.

## Winning principles
1. **Engine > UI decoration.**
2. Prove universality with 5 genuinely different sources, not 50 fake parsers.
3. Every normalized event must lead back to the exact raw event.
4. New-source onboarding must not require rewriting the core.
5. Known sources use deterministic parsers; AI is optional assistance for unknown-source onboarding.
6. Core demo must work without internet.
7. Publish measured accuracy/throughput; never invent benchmark numbers.

## Phase map
| Phase | Goal | Exit condition |
|---|---|---|
| 0 | Scope & contracts | Schema + taxonomy + plugin contract locked |
| 1 | Core engine | One source works end-to-end |
| 2 | Multi-vendor | 5 sources normalize into one schema |
| 3 | Outstanding UX | Explorer + hero inspector + registry |
| 4 | Hardening | Offline Docker + benchmark + unknown-source flow |
| 5 | Hackathon packaging | Reliable 2-min demo + docs + pitch |
| 6 | SIH expansion | Streaming scale, more adapters, integrations |

## MVP scope
### Must
- Cisco ASA, FortiGate, Palo Alto, generic Syslog, CEF
- source/format detection
- parser registry
- universal schema
- value normalization
- immutable raw-event preservation
- normalized↔raw traceability
- unknown-event quarantine
- event explorer/search
- Raw → Parsed → Normalized inspector
- JSON/NDJSON export API
- Dockerized offline run
- automated tests and benchmark

### Stretch
- AI-assisted parser/mapping suggestion
- Kafka-compatible ingestion
- OpenSearch output
- ECS/OCSF export mappings

### Do NOT build first
- full SIEM
- threat-detection platform
- hundreds of vendors
- cloud-dependent core
- auto-activation of AI-generated parsers
- fake “billions/day” claim

## Team coordination
- **Aditya Jain:** lead, architecture/integration, scope and demo readiness.
- **Vishwajeet Singh:** backend engine, provenance, storage/API, Docker/benchmark.
- **Shaurya:** frontend explorer, inspector, registry/onboarding UX.
- **Pawani Sanghi:** pitch/product/QA, fixtures, acceptance tests, demo story; can contribute across code.

Every feature gets **one owner + one reviewer**.

## Definition of done
- Clean clone runs from README.
- Mixed demo dataset is reproducible.
- Supported adapters have tests.
- Raw payload is retrievable for every normalized event.
- Parser and mapping versions are recorded.
- Unknown logs fail safely.
- Benchmark numbers come from a script.
- Core demo works with internet disconnected.
- Three consecutive rehearsals succeed.
