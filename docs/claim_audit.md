# Claim Audit

## Safe claims

- Supports five prototype adapters: FortiGate, Cisco ASA, Palo Alto PAN-OS, CEF and Generic RFC5424 Syslog.
- Uses a stable universal schema with raw evidence and provenance.
- Unknown events are retained and quarantined.
- Onboarding assistance is offline/rule-based in this prototype.
- Generated/draft mappings are not auto-activated.
- NDJSON export and normalized JSON API are available.
- Air-gap process-level proof passed.
- Docker and Compose packaging are included.
- Local benchmark is reproducible using `scripts/benchmark.py`.

## Avoid these claims

Do not claim production billion-event/day throughput, production accuracy from synthetic fixtures, real operational telemetry, AI-required parsing for known sources, or full SIEM/threat-detection capability.

## Correct scale wording

"ULPF demonstrates a horizontally scalable architecture path using ingress, queue, stateless workers and normalized output. The current numbers are local single-process prototype measurements."
