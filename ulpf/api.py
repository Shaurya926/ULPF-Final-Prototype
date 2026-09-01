from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .errors import ContractError, SecurityError
from .onboarding import analyze_payload, preview_mapping
from .pipeline import CoreEngine
from .registry import PluginRegistry, evaluate_detection_rules
from .storage import SQLiteStore
from .security import SecurityLimits


class PasteRequest(BaseModel):
    payload: str = Field(min_length=1)


class BatchRequest(BaseModel):
    payloads: list[str] = Field(min_length=1, max_length=10000)


class PluginStateRequest(BaseModel):
    enabled: bool


class OnboardingAnalyzeRequest(BaseModel):
    payload: str = Field(min_length=1)


class OnboardingPreviewRequest(BaseModel):
    payload: str = Field(min_length=1)
    mappings: dict[str, str]
    vendor: str = Field(default="Unknown", min_length=1, max_length=100)
    product: str = Field(default="Unknown", min_length=1, max_length=100)
    plugin_id: str = Field(default="draft_plugin", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


class OnboardingDraftRequest(OnboardingPreviewRequest):
    pass


class DraftTestRequest(BaseModel):
    payload: str = Field(min_length=1)
    detection_rules: dict[str, Any] | None = None


class DraftRegisterRequest(BaseModel):
    detection_rules: dict[str, Any] | None = None
    fixtures: list[str] | None = None


class OnboardingFixtureValidationRequest(BaseModel):
    payloads: list[str] = Field(min_length=1, max_length=100)
    mappings: dict[str, str]
    vendor: str = Field(default="Unknown", min_length=1, max_length=100)
    product: str = Field(default="Unknown", min_length=1, max_length=100)
    plugin_id: str = Field(default="draft_plugin", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


def create_app(db_path: str | None = None, plugin_root: str | None = None) -> FastAPI:
    package_root = Path(__file__).resolve().parent.parent
    db_path = db_path or os.getenv("ULPF_DB_PATH", str(package_root / "data" / "ulpf.db"))
    plugin_root = plugin_root or os.getenv("ULPF_PLUGIN_DIR", str(package_root / "plugins"))

    store = SQLiteStore(db_path)
    registry = PluginRegistry(plugin_root)
    engine = CoreEngine(store, registry)
    security_limits = SecurityLimits.from_env()
    static_dir = Path(__file__).resolve().parent / "static"
    datasets_dir = package_root / "datasets"

    app = FastAPI(
        title="ULPF Prototype",
        version="1.0.0",
        description="Vendor-agnostic, lossless cyber-event translation layer — final SIH hackathon-ready prototype.",
    )
    app.state.store = store
    app.state.registry = registry
    app.state.engine = engine

    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    @app.get("/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "plugins": len(registry.plugins),
            "phase": 5,
            "offline_core": True,
            "authoring_assistance": "RULE_BASED_OFFLINE",
            "ai_required": False,
            "security_limits": {
                "max_event_bytes": security_limits.max_event_bytes,
                "max_file_bytes": security_limits.max_file_bytes,
                "max_batch_events": security_limits.max_batch_events,
                "max_batch_bytes": security_limits.max_batch_bytes,
            },
        }

    @app.get("/api/v1/overview")
    def overview() -> dict[str, object]:
        data = store.overview()
        data["active_plugins"] = len(registry.plugins)
        data["offline_core"] = True
        data["throughput_label"] = "Last local ingestion measurement (not a benchmark)"
        benchmark_path = package_root / "reports" / "phase4_benchmark.json"
        if benchmark_path.exists():
            try:
                benchmark = json.loads(benchmark_path.read_text(encoding="utf-8"))
                data["published_benchmark"] = {
                    "events_per_sec": benchmark.get("events_per_sec"),
                    "p50_ms": benchmark.get("latency_ms", {}).get("p50"),
                    "p95_ms": benchmark.get("latency_ms", {}).get("p95"),
                    "failure_rate": benchmark.get("failure_rate"),
                    "events": benchmark.get("events"),
                    "generated_at": benchmark.get("generated_at"),
                    "label": "Reproducible local single-process benchmark",
                }
            except (json.JSONDecodeError, OSError):
                data["published_benchmark"] = None
        else:
            data["published_benchmark"] = None
        return data

    @app.get("/api/v1/plugins")
    def plugins() -> list[dict[str, object]]:
        return registry.list_plugins()

    @app.patch("/api/v1/plugins/{plugin_id}/state")
    def plugin_state(plugin_id: str, body: PluginStateRequest) -> dict[str, object]:
        try:
            before = registry.plugin_summary(plugin_id)["enabled"]
            result = registry.set_enabled(plugin_id, body.enabled)
            store.record_audit(
                actor="local_operator",
                action="PLUGIN_STATE_CHANGED",
                object_type="plugin",
                object_id=plugin_id,
                details={"before": before, "after": body.enabled, "scope": "runtime"},
            )
            return result
        except ContractError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    def _record(source: str, payloads: list[str]):
        try:
            security_limits.validate_batch(payloads)
        except SecurityError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        started = time.perf_counter()
        results = engine.process_batch(payloads)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        store.record_processing_metric(source=source, batch_size=len(payloads), elapsed_ms=elapsed_ms)
        return results

    @app.post("/api/v1/ingest/paste")
    def ingest_paste(body: PasteRequest) -> dict[str, object]:
        return _record("paste", [body.payload])[0].model_dump(mode="json")

    @app.post("/api/v1/ingest/batch")
    def ingest_batch(body: BatchRequest) -> list[dict[str, object]]:
        return [item.model_dump(mode="json") for item in _record("batch", body.payloads)]

    @app.post("/api/v1/ingest/file")
    async def ingest_file(
        request: Request,
        split_lines: bool = Query(True, description="Treat each non-empty line as an event"),
    ) -> list[dict[str, object]]:
        body = await request.body()
        try:
            security_limits.validate_file_bytes(body)
        except SecurityError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="file body must be UTF-8 text") from exc
        payloads = [line for line in text.splitlines() if line.strip()] if split_lines else [text]
        if not payloads:
            raise HTTPException(status_code=400, detail="no log events found")
        return [item.model_dump(mode="json") for item in _record("file", payloads)]

    @app.get("/api/v1/demo/datasets")
    def demo_datasets() -> list[dict[str, str]]:
        return [
            {"id": "mixed", "label": "5-vendor sample batch (ALLOW + DENY)", "file": "judge_demo.log"},
            {"id": "unknown", "label": "Unknown source sample", "file": "unknown/unknown_1.log"},
        ]

    @app.get("/api/v1/demo/datasets/{dataset_id}")
    def demo_dataset(dataset_id: str) -> dict[str, object]:
        mapping = {
            "mixed": datasets_dir / "judge_demo.log",
            "unknown": datasets_dir / "unknown" / "unknown_1.log",
        }
        path = mapping.get(dataset_id)
        if not path or not path.exists():
            raise HTTPException(status_code=404, detail="demo dataset not found")
        text = path.read_text(encoding="utf-8")
        return {
            "id": dataset_id,
            "payload": text,
            "events": [line for line in text.splitlines() if line.strip()],
            "synthetic": True,
            "label": "Sanitized/synthetic demo telemetry",
        }

    @app.get("/api/v1/events")
    def list_events(
        limit: int = Query(250, ge=1, le=1000),
        action: str | None = None,
        vendor: str | None = None,
        product: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        protocol: str | None = None,
        category: str | None = None,
        plugin_id: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, object]]:
        return store.query_events(
            limit=limit,
            action=action,
            vendor=vendor,
            product=product,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            category=category,
            plugin_id=plugin_id,
            search=search,
        )

    @app.get("/api/v1/events/{event_id}")
    def get_event(event_id: str) -> dict[str, object]:
        event = store.get_event(event_id)
        if not event:
            raise HTTPException(status_code=404, detail="event not found")
        return event

    @app.get("/api/v1/events/{event_id}/inspect")
    def inspect_event(event_id: str) -> dict[str, object]:
        data = store.get_inspection(event_id)
        if not data:
            raise HTTPException(status_code=404, detail="event not found")
        return data

    @app.get("/api/v1/events/{event_id}/raw")
    def raw_from_event(event_id: str) -> dict[str, object]:
        event = store.get_event(event_id)
        if not event:
            raise HTTPException(status_code=404, detail="event not found")
        raw = store.get_raw(event["raw"]["event_id"])
        if not raw:
            raise HTTPException(status_code=404, detail="raw event not found")
        return raw

    @app.get("/api/v1/raw/{raw_event_id}")
    def get_raw(raw_event_id: str) -> dict[str, object]:
        raw = store.get_raw(raw_event_id)
        if not raw:
            raise HTTPException(status_code=404, detail="raw event not found")
        return raw

    @app.get("/api/v1/quarantine")
    def quarantine(limit: int = Query(100, ge=1, le=1000)) -> list[dict[str, object]]:
        return store.list_quarantine(limit)

    @app.get("/api/v1/export/ndjson")
    def export_ndjson(limit: int = Query(10000, ge=1, le=100000)) -> Response:
        events = store.export_events(limit)
        body = "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)
        return Response(
            content=body,
            media_type="application/x-ndjson",
            headers={"Content-Disposition": "attachment; filename=ulpf-events.ndjson"},
        )

    @app.get("/api/v1/audit")
    def audit(limit: int = Query(100, ge=1, le=1000)) -> list[dict[str, object]]:
        return store.list_audit(limit)

    @app.post("/api/v1/onboarding/analyze")
    def onboarding_analyze(body: OnboardingAnalyzeRequest) -> dict[str, object]:
        try:
            security_limits.validate_payload(body.payload)
        except SecurityError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        return analyze_payload(body.payload)

    @app.post("/api/v1/onboarding/preview")
    def onboarding_preview(body: OnboardingPreviewRequest) -> dict[str, object]:
        try:
            security_limits.validate_payload(body.payload)
        except SecurityError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        return preview_mapping(
            payload=body.payload,
            mappings=body.mappings,
            vendor=body.vendor,
            product=body.product,
            plugin_id=body.plugin_id,
        )

    @app.post("/api/v1/onboarding/validate-fixtures")
    def validate_onboarding_fixtures(body: OnboardingFixtureValidationRequest) -> dict[str, object]:
        try:
            security_limits.validate_batch(body.payloads)
        except SecurityError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        previews = [
            preview_mapping(
                payload=payload, mappings=body.mappings, vendor=body.vendor,
                product=body.product, plugin_id=body.plugin_id
            )
            for payload in body.payloads
        ]
        ready = sum(1 for item in previews if item["validation"]["ready_for_plugin_review"])
        return {
            "plugin_id": body.plugin_id,
            "fixtures": len(previews),
            "ready": ready,
            "failed": len(previews) - ready,
            "all_ready": ready == len(previews),
            "auto_activated": False,
            "results": [item["validation"] for item in previews],
        }

    @app.post("/api/v1/onboarding/drafts")
    def save_onboarding_draft(body: OnboardingDraftRequest) -> dict[str, object]:
        try:
            security_limits.validate_payload(body.payload)
        except SecurityError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        preview = preview_mapping(
            payload=body.payload,
            mappings=body.mappings,
            vendor=body.vendor,
            product=body.product,
            plugin_id=body.plugin_id,
        )
        result = store.save_onboarding_draft(
            plugin_id=body.plugin_id,
            vendor=body.vendor,
            product=body.product,
            payload=body.payload,
            analysis=preview["analysis"],
            mappings=body.mappings,
            preview=preview,
        )
        store.record_audit(
            actor="local_operator",
            action="PLUGIN_DRAFT_CREATED",
            object_type="onboarding_draft",
            object_id=result["draft_id"],
            details={
                "plugin_id": body.plugin_id,
                "ready_for_review": preview["validation"]["ready_for_plugin_review"],
                "auto_activated": False,
                "authoring_mode": "RULE_BASED_OFFLINE",
            },
        )
        return result

    @app.get("/api/v1/onboarding/drafts")
    def onboarding_drafts(limit: int = Query(50, ge=1, le=200)) -> list[dict[str, object]]:
        return store.list_onboarding_drafts(limit)

    @app.get("/api/v1/onboarding/drafts/{draft_id}")
    def get_onboarding_draft(draft_id: str) -> dict[str, object]:
        draft = store.get_onboarding_draft(draft_id)
        if not draft:
            raise HTTPException(status_code=404, detail="draft not found")
        return draft

    @app.post("/api/v1/onboarding/drafts/{draft_id}/test")
    def test_onboarding_draft(draft_id: str, body: DraftTestRequest) -> dict[str, object]:
        draft = store.get_onboarding_draft(draft_id)
        if not draft:
            raise HTTPException(status_code=404, detail="draft not found")
        try:
            security_limits.validate_payload(body.payload)
        except SecurityError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        rules = body.detection_rules or draft["analysis"].get("suggested_detection") or {"rules": {}}
        detection = evaluate_detection_rules(rules, body.payload, plugin_id=draft["plugin_id"])
        preview = preview_mapping(
            payload=body.payload,
            mappings=draft["mappings"],
            vendor=draft["vendor"],
            product=draft["product"],
            plugin_id=draft["plugin_id"],
        )
        return {
            "detection": detection,
            "normalized_preview": preview["normalized_preview"],
            "validation": preview["validation"],
        }

    @app.post("/api/v1/onboarding/drafts/{draft_id}/register")
    def register_onboarding_draft(draft_id: str, body: DraftRegisterRequest) -> dict[str, object]:
        draft = store.get_onboarding_draft(draft_id)
        if not draft:
            raise HTTPException(status_code=404, detail="draft not found")
        if draft["status"] == "REGISTERED":
            raise HTTPException(status_code=409, detail="draft already registered")
        plugin_id = draft["plugin_id"]
        if plugin_id in registry._all_plugins:
            raise HTTPException(status_code=409, detail=f"a parser with id {plugin_id!r} already exists")

        detection = body.detection_rules or draft["analysis"].get("suggested_detection") or {"rules": {}}
        mapping_config = draft["preview"].get("draft_mapping_config") or {}
        manifest = {
            "id": plugin_id,
            "version": "1.0.0",
            "vendor": draft["vendor"],
            "product": draft["product"],
            "format": draft["analysis"].get("format_hint", "text"),
            "enabled": True,
            "parser": {"file": "parser.py", "function": "parse"},
            "detection": "detection.yaml",
            "mappings": "mappings.yaml",
        }
        fixtures = body.fixtures or [draft["payload"]]
        try:
            registry.write_plugin(
                plugin_id,
                manifest=manifest,
                detection=detection,
                mappings=mapping_config,
                fixtures=fixtures,
            )
            registry.reload()
        except ContractError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        store.update_onboarding_draft_status(draft_id, "REGISTERED")
        store.record_audit(
            actor="local_operator",
            action="PARSER_REGISTERED",
            object_type="plugin",
            object_id=plugin_id,
            details={"draft_id": draft_id, "source": "onboarding_draft"},
        )
        return registry.plugin_summary(plugin_id)

    return app


app = create_app()
