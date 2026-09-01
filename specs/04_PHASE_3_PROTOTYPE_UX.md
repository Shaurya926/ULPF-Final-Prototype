# Phase 3 — Outstanding Prototype UX

## Goal
Make backend depth obvious to judges in under two minutes.

## Screen 1 — Overview
Show:
- total events
- parsed
- unknown/failed
- active plugins
- vendor distribution
- action/category distribution
- measured throughput

Do not fake a threat-intelligence/SOC dashboard.

## Screen 2 — Ingestion
- upload/paste logs
- batch processing
- sample demo datasets
- processing states

## Screen 3 — Unified Event Explorer
Columns:
timestamp, vendor, product, source IP, destination IP, port, protocol, action, category, parser version, status.

Filters must work **across vendors**.

## Screen 4 — Hero Event Inspector
Three clear views:
**RAW → PARSED → NORMALIZED**

Also show:
- raw event ID
- normalized event ID
- parser/mapping versions
- field-level trace
- vendor extensions
- validation result

This single screen proves parsing, normalization, losslessness and traceability.

## Screen 5 — Parser Registry
Show active adapters, versions, formats, detection-rule summary, tests and enable/disable state.

## Screen 6 — Unknown Event / Onboarding
Show sample payload, detected structure, mapping editor, validation preview and save-as-plugin flow.

## 90-second judge flow
1. Load mixed vendor dataset.
2. Process.
3. Show unified table.
4. Filter `event.action = DENY`.
5. Open FortiGate event and inspect transformations.
6. Open equivalent Cisco event and show same taxonomy.
7. Show unknown source.
8. Preview onboarding/new plugin.
9. End on benchmark + offline status.

## Exit
A non-cybersecurity judge can accurately explain the product after the demo.
