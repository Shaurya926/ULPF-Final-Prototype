# Phase 4 Completion — Innovation, Scale, Security & Air-Gap

## Status

**Implementation complete through Phase 4.**

Phase 4 hardens the Phase 0–3 engine without weakening deterministic known-source processing.

## AI-assisted / parser-authoring guardrails

The prototype uses **offline rule-based authoring assistance** for unknown sources; no external AI service is required.

- structure inference for JSON, key/value, timestamp/IP/token hints;
- suggested universal mappings;
- each suggestion now includes confidence and evidence;
- `RULE_BASED_OFFLINE` authoring mode is explicit;
- mapping previews remain non-activating;
- multi-fixture validation endpoint tests a proposed mapping across samples;
- onboarding drafts remain `DRAFT_REVIEW_REQUIRED`;
- `auto_activated = false` is enforced in responses and audit records.

Known sources still use deterministic plugins only.

## Security hardening

Implemented:

- `ULPF_MAX_EVENT_BYTES` — default 64 KiB;
- `ULPF_MAX_FILE_BYTES` — default 5 MiB;
- `ULPF_MAX_BATCH_EVENTS` — default 10,000;
- `ULPF_MAX_BATCH_BYTES` — default 5 MiB;
- plugin file size limit — default 256 KiB;
- oversized events are rejected **before raw persistence**;
- path traversal and plugin symlink escape are rejected;
- YAML uses safe loading;
- raw browser rendering uses escaped/text-only sinks;
- exact raw SHA-256 remains attached to normalized records;
- runtime plugin state changes are audited;
- plugin/onboarding draft creation is audited;
- no uploaded log content is executed.

## Interoperability

- normalized JSON API remains available;
- NDJSON export added at `GET /api/v1/export/ndjson`;
- raw-event retrieval and normalized↔raw traceability remain intact.

## Reproducible benchmark

Command:

```bash
python scripts/benchmark.py --events 500
```

Generated reports:

- `reports/phase4_benchmark.json`
- `reports/phase4_benchmark.md`

Measured in the provided build runtime on 500 repeated synthetic judge-demo events:

- throughput: **66.58 events/sec**;
- p50: **11.22 ms**;
- p95: **27.19 ms**;
- failure rate: **0.00%**;
- batch duration: **7.509 s**;
- max RSS observed after run: **139.89 MiB**;
- reported CPU count: **5**;
- Python: **3.13.5**.

These numbers are a **single-process deterministic engine + SQLite prototype baseline**. HTTP/network are excluded. They are not production-scale or billion-event/day claims.

## Scale architecture

`architecture/SCALE_ARCHITECTURE.md` records the intended topology:

`Ingress → bounded queue → stateless workers → normalized output`

The current benchmark deliberately measures one worker first. The correct claim is **horizontally scalable architecture**, not unverified production scale.

## Air-gap

`python scripts/airgap_check.py` passes the local no-network proof for:

- engine startup;
- ingestion;
- normalization;
- inspection;
- export;
- restart/reconstruction;
- SQLite persistence.

Docker packaging is included:

- `Dockerfile`;
- `docker-compose.yml`;
- `.dockerignore`;
- persistent `ulpf_data` volume;
- non-root container user;
- environment-based limits/configuration;
- `AIRGAP_RUNBOOK.md` with `docker compose up --no-build` workflow.

**Build-environment limitation:** no Docker/Podman-compatible runtime is installed in the current execution environment, so an actual container launch could not be executed here. The repository therefore distinguishes the passing process-level air-gap proof from the container-host verification that the team must run on a machine with Docker.

## Verification

Current automated suite:

```text
33 passed
```

Phase 4-specific coverage includes:

- pre-persistence oversize rejection;
- file/batch HTTP 413 behavior;
- plugin path traversal rejection;
- NDJSON export;
- raw SHA-256 equality;
- authoring confidence/evidence;
- non-auto-activation;
- fixture-validation gate;
- onboarding audit entry;
- plugin runtime-state audit entry.

Frontend JavaScript also passes `node --check`.

## Exit-condition assessment

- Reproducible benchmark: **PASS**
- Safe failure paths/security limits: **PASS**
- Innovation remains outside deterministic hot path: **PASS**
- Process-level offline demo + persistence: **PASS**
- Dockerized offline packaging: **IMPLEMENTED**
- Actual Docker air-gap launch in this build environment: **NOT EXECUTABLE HERE (runtime absent)**

No later Phase 5 packaging/pitch work is included yet.
