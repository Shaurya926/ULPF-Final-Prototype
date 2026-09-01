# Phase 0 Contract Lock

Phase 0 decisions are frozen for the inter-college prototype.

## Locked supported-source target

1. Cisco ASA
2. Fortinet FortiGate
3. Palo Alto
4. Generic Syslog
5. CEF

Only FortiGate is implemented in Phase 1; the remaining adapters are Phase 2 work and must use the same plugin contract.

## Locked contracts

- Universal Event Schema: v0.1 (`universal_event.schema.json`)
- Taxonomy: v0.1 (`taxonomy.yaml`)
- Plugin Contract: v0.1 (`PLUGIN_CONTRACT.md`)
- Raw preservation: exact UTF-8 event payload stored before transformation
- Provenance: parser ID/version, mapping version, deterministic detection evidence, per-field trace
- Unknown-source behavior: quarantine, never guess

## Demo story lock

1. Show an original FortiGate firewall event.
2. Ingest it through the API.
3. Show deterministic FortiGate detection evidence.
4. Show source-shaped parsed fields.
5. Show normalized universal event with normalized action/transport/timestamp.
6. Show unmapped vendor fields preserved in `extensions.fortigate`.
7. Follow `raw.event_id` back to the byte-identical raw event and SHA-256.
8. Feed a malformed/unknown log and show safe quarantine.

## Initial ownership

- Architecture/integration and demo readiness: Aditya Jain
- Backend engine, provenance, storage/API: Vishwajeet Singh
- Explorer/inspector/registry UX: Shaurya
- Fixtures, QA, acceptance tests, demo story: Pawani Sanghi

Each implementation item should have one owner and one reviewer before merge.

## Exit checklist

- [x] Five source targets locked
- [x] Schema v0.1 locked
- [x] Taxonomy v0.1 locked
- [x] Plugin contract v0.1 locked
- [x] Demo story locked
- [x] Initial ownership recorded
