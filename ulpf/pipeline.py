from __future__ import annotations

import json
from uuid import uuid4

from pydantic import ValidationError

from .errors import ULPFError
from .mapper import map_event
from .models import DetectionAttempt, ProcessResult, UniversalEvent
from .registry import PluginRegistry
from .storage import SQLiteStore
from .security import SecurityLimits


class CoreEngine:
    def __init__(self, store: SQLiteStore, registry: PluginRegistry):
        self.store = store
        self.registry = registry
        self.security_limits = SecurityLimits.from_env()

    def process(self, payload: str) -> ProcessResult:
        # Reject oversized input before it can be persisted or parsed.
        self.security_limits.validate_payload(payload)
        raw = self.store.create_raw(payload)
        raw_id = raw["raw_event_id"]
        detection_report: list[DetectionAttempt] | None = None

        try:
            detection, detection_report = self.registry.detect_with_report(payload)
            if detection is None:
                details = {
                    "message": "no deterministic plugin matched",
                    "detection_report": [item.model_dump(mode="json") for item in detection_report],
                }
                self.store.quarantine(raw_id, "UNKNOWN_SOURCE", json.dumps(details, sort_keys=True))
                return ProcessResult(
                    status="QUARANTINED",
                    raw_event_id=raw_id,
                    reason="UNKNOWN_SOURCE",
                    detection_report=detection_report,
                )
            self.store.update_status(raw_id, "DETECTED")

            plugin = self.registry.resolve(detection.plugin_id)
            parsed = plugin.parser(payload)
            if not isinstance(parsed, dict) or not parsed:
                raise ValueError("parser returned no source fields")
            self.store.update_status(raw_id, "PARSED")

            mapped, field_trace = map_event(parsed, plugin.mappings)
            self.store.update_status(raw_id, "NORMALIZED")

            event_id = f"evt_{uuid4().hex}"
            mapped["event_id"] = event_id
            mapped["raw"] = {
                "event_id": raw_id,
                "payload": payload,
                "sha256": raw["sha256"],
            }
            mapped["provenance"] = {
                "parser_id": plugin.id,
                "parser_version": plugin.manifest["version"],
                "mapping_version": plugin.mappings["mapping_version"],
                "detection_confidence": detection.confidence,
                "detection_evidence": detection.evidence,
                "field_trace": field_trace,
            }

            normalized_model = UniversalEvent.model_validate(mapped)
            normalized = normalized_model.model_dump(mode="json", by_alias=True, exclude_none=True)

            self.store.save_normalized(
                event_id=event_id,
                raw_event_id=raw_id,
                plugin_id=plugin.id,
                detection=detection.model_dump(mode="json"),
                parsed=parsed,
                normalized=normalized,
            )
            return ProcessResult(
                status="STORED",
                raw_event_id=raw_id,
                event_id=event_id,
                plugin_id=plugin.id,
            )
        except (ULPFError, ValidationError, ValueError, TypeError) as exc:
            details = {
                "message": str(exc),
                "detection_report": [item.model_dump(mode="json") for item in (detection_report or [])],
            }
            self.store.quarantine(
                raw_id,
                exc.__class__.__name__.upper(),
                json.dumps(details, sort_keys=True),
            )
            return ProcessResult(
                status="QUARANTINED",
                raw_event_id=raw_id,
                reason=exc.__class__.__name__.upper(),
                detection_report=detection_report,
            )

    def process_batch(self, payloads: list[str]) -> list[ProcessResult]:
        self.security_limits.validate_batch(payloads)
        return [self.process(payload) for payload in payloads]
