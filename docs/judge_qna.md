# Judge Q&A Cheat Sheet

**Why not a SIEM parser?** ULPF is a reusable preprocessing layer before SIEM/data-lake/ML systems.

**Why not just ECS or OCSF?** Schemas are targets. ULPF is the processing framework around the target: ingestion, detection, parsing, mapping, validation, provenance, quarantine, onboarding and export.

**Where is AI?** AI or rule-based assistance belongs at the expensive human step: unknown-source onboarding. Known high-volume sources remain deterministic and offline.

**Can it handle billions per day?** We do not claim that without deployment evidence. We show measured prototype throughput and a horizontally scalable ingress → queue → stateless worker architecture.

**How is it lossless?** Every normalized event references the exact raw payload. Unknown and unmapped fields remain accessible through raw evidence and extensions.

**How do you avoid wrong parsing?** Deterministic detection evidence, plugin validation, fixture tests, schema validation and quarantine prevent silent wrong parsing.
