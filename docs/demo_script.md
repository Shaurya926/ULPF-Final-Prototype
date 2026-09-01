# 2-Minute Demo Script

**0–20s:** "Every firewall and perimeter device speaks a different log language. ULPF creates one lossless event language before SIEMs, data lakes or analytics." Show the mixed raw dataset.

**20–45s:** Click **Load 5-vendor judge batch**, then **Process batch**. Say: "The core stores raw first, detects source, selects a plugin, parses, maps, normalizes, validates and exports. This works offline."

**45–75s:** Open Explorer and filter `event.action = DENY`. Say: "DENY works as one filter across FortiGate, Cisco ASA, Palo Alto, CEF and Syslog."

**75–100s:** Open a FortiGate ALLOW event. Show **RAW → PARSED → NORMALIZED** and field trace. Then open the equivalent Cisco ALLOW event and show the same normalized action.

**100–115s:** Load the unknown-source sample. Say: "Unknown logs are retained and quarantined with detection evidence. Mapping help saves a draft only; it never auto-activates."

**115–120s:** Show benchmark/offline status. Close: "ULPF is an offline-capable, deterministic, plugin-based preprocessing framework with measured prototype throughput and a horizontally scalable architecture path."
