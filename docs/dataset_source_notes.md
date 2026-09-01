# Dataset and Source Notes

All demo telemetry in this repository is synthetic or sanitized prototype fixture data. It is designed to exercise parser behavior and cross-vendor normalization, not to represent production security operations.

- `datasets/judge_demo.log` — 10-event judge flow: five vendors with one ALLOW and one DENY event each.
- `datasets/mixed_batch.log` — Phase 2 cross-vendor equivalence corpus.
- `datasets/<vendor>/allow.log` and `deny.log` — vendor-specific fixtures.
- `datasets/<vendor>/unmapped.log` — extra vendor-only fields for extension preservation.
- `datasets/malformed/` — malformed records for safe-failure tests.
- `datasets/unknown/` — unknown-source onboarding/quarantine samples.

Presentation wording: "These are synthetic/sanitized demo logs built to prove parser and normalization behavior."
