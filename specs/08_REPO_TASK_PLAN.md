# Repository & Task Plan

## Monorepo
```text
ulpf/
├─ backend/
│  ├─ app/
│  │  ├─ api/
│  │  ├─ ingestion/
│  │  ├─ detection/
│  │  ├─ registry/
│  │  ├─ mapping/
│  │  ├─ normalization/
│  │  ├─ validation/
│  │  ├─ provenance/
│  │  └─ storage/
│  └─ tests/
├─ frontend/
├─ plugins/
│  ├─ fortigate/
│  ├─ cisco_asa/
│  ├─ palo_alto/
│  ├─ cef/
│  └─ syslog/
├─ datasets/
├─ benchmarks/
├─ docs/
│  ├─ architecture.md
│  ├─ schema.md
│  └─ adr/
├─ docker/
├─ docker-compose.yml
└─ README.md
```

## Git rules
- `main` always demoable.
- Use `feat/<name>` branches.
- Small PRs with one reviewer.
- Parser changes require fixtures/tests.
- Tag stable demo builds.

## Issue priorities
### P0
Schema, plugin contract, raw persistence, FortiGate vertical slice, API, event inspector, remaining four adapters, mixed-batch integration, Docker offline run, demo dataset.

### P1
Registry UI, unknown queue, mapping editor, benchmark harness, metrics, field provenance.

### P2
AI parser assistant, ECS/OCSF exporter, streaming queue, OpenSearch connector.

## Ownership
| Area | Primary | Reviewer |
|---|---|---|
| Architecture/integration | Aditya | Vishwajeet |
| Core backend | Vishwajeet | Aditya |
| Frontend | Shaurya | Pawani |
| Fixtures/QA | Pawani | Vishwajeet |
| Pitch/demo | Pawani | Aditya |
| Docker/benchmark | Vishwajeet | Aditya |
| Onboarding UX | Shaurya | Vishwajeet |

Ownership coordinates work; it does not stop cross-contribution.
