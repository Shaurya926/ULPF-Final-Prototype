from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class SQLiteStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS raw_events (
                    raw_event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    byte_length INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS normalized_events (
                    event_id TEXT PRIMARY KEY,
                    raw_event_id TEXT NOT NULL UNIQUE,
                    plugin_id TEXT NOT NULL,
                    detection_json TEXT NOT NULL,
                    parsed_json TEXT NOT NULL,
                    normalized_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(raw_event_id) REFERENCES raw_events(raw_event_id)
                );

                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    raw_event_id TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL,
                    details TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(raw_event_id) REFERENCES raw_events(raw_event_id)
                );

                CREATE TABLE IF NOT EXISTS processing_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    batch_size INTEGER NOT NULL,
                    elapsed_ms REAL NOT NULL,
                    events_per_sec REAL NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS onboarding_drafts (
                    draft_id TEXT PRIMARY KEY,
                    plugin_id TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    product TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    analysis_json TEXT NOT NULL,
                    mappings_json TEXT NOT NULL,
                    preview_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def create_raw(self, payload: str) -> dict[str, Any]:
        raw_event_id = f"raw_{uuid4().hex}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO raw_events
                (raw_event_id,payload,sha256,byte_length,status,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?)""",
                (
                    raw_event_id,
                    payload,
                    digest,
                    len(payload.encode("utf-8")),
                    "RECEIVED",
                    now,
                    now,
                ),
            )
        return {"raw_event_id": raw_event_id, "sha256": digest, "payload": payload}

    def update_status(self, raw_event_id: str, status: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE raw_events SET status=?, updated_at=? WHERE raw_event_id=?",
                (status, _now(), raw_event_id),
            )

    def save_normalized(
        self,
        *,
        event_id: str,
        raw_event_id: str,
        plugin_id: str,
        detection: dict[str, Any],
        parsed: dict[str, Any],
        normalized: dict[str, Any],
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO normalized_events
                (event_id,raw_event_id,plugin_id,detection_json,parsed_json,normalized_json,created_at)
                VALUES (?,?,?,?,?,?,?)""",
                (
                    event_id,
                    raw_event_id,
                    plugin_id,
                    json.dumps(detection, sort_keys=True),
                    json.dumps(parsed, sort_keys=True),
                    json.dumps(normalized, sort_keys=True),
                    _now(),
                ),
            )
        self.update_status(raw_event_id, "STORED")

    def quarantine(self, raw_event_id: str, reason: str, details: str | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO quarantine (raw_event_id,reason,details,created_at) VALUES (?,?,?,?)",
                (raw_event_id, reason, details, _now()),
            )
        self.update_status(raw_event_id, "QUARANTINED")

    def get_raw(self, raw_event_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM raw_events WHERE raw_event_id=?", (raw_event_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT normalized_json FROM normalized_events WHERE event_id=?", (event_id,)
            ).fetchone()
        return json.loads(row["normalized_json"]) if row else None

    def get_inspection(self, event_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT n.*, r.payload, r.sha256, r.status AS raw_status
                   FROM normalized_events n
                   JOIN raw_events r ON r.raw_event_id=n.raw_event_id
                   WHERE n.event_id=?""",
                (event_id,),
            ).fetchone()
        if not row:
            return None
        normalized = json.loads(row["normalized_json"])
        return {
            "event_id": row["event_id"],
            "raw_event_id": row["raw_event_id"],
            "plugin_id": row["plugin_id"],
            "detection": json.loads(row["detection_json"]),
            "raw": {"payload": row["payload"], "sha256": row["sha256"], "status": row["raw_status"]},
            "parsed": json.loads(row["parsed_json"]),
            "normalized": normalized,
            "validation": {"status": "PASS", "schema": "universal_event_v0.1"},
            "field_trace": normalized.get("provenance", {}).get("field_trace", {}),
            "extensions": normalized.get("extensions", {}),
        }

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT normalized_json FROM normalized_events ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row["normalized_json"]) for row in rows]

    def query_events(
        self,
        *,
        limit: int = 250,
        action: str | None = None,
        vendor: str | None = None,
        product: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        protocol: str | None = None,
        category: str | None = None,
        plugin_id: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        # The prototype keeps JSON intact for losslessness; filtering is intentionally
        # performed in application code until a later indexed-store phase.
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT n.normalized_json, n.plugin_id, r.status
                   FROM normalized_events n JOIN raw_events r ON r.raw_event_id=n.raw_event_id
                   ORDER BY n.created_at DESC LIMIT 5000"""
            ).fetchall()

        def eq(value: Any, expected: str | None) -> bool:
            return expected is None or str(value or "").lower() == expected.lower()

        results: list[dict[str, Any]] = []
        for row in rows:
            event = json.loads(row["normalized_json"])
            if not eq(event.get("event", {}).get("action"), action):
                continue
            if not eq(event.get("observer", {}).get("vendor"), vendor):
                continue
            if not eq(event.get("observer", {}).get("product"), product):
                continue
            if not eq(event.get("source", {}).get("ip"), source_ip):
                continue
            if not eq(event.get("destination", {}).get("ip"), destination_ip):
                continue
            if not eq(event.get("network", {}).get("transport"), protocol):
                continue
            if not eq(event.get("event", {}).get("category"), category):
                continue
            if plugin_id and row["plugin_id"].lower() != plugin_id.lower():
                continue
            if search:
                haystack = json.dumps(event, sort_keys=True).lower()
                if search.lower() not in haystack:
                    continue
            event["_status"] = row["status"]
            results.append(event)
            if len(results) >= limit:
                break
        return results

    def list_quarantine(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT q.*, r.payload, r.sha256, r.status
                   FROM quarantine q JOIN raw_events r USING(raw_event_id)
                   ORDER BY q.created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            if item.get("details"):
                try:
                    item["details"] = json.loads(item["details"])
                except (json.JSONDecodeError, TypeError):
                    pass
            results.append(item)
        return results

    def record_processing_metric(self, *, source: str, batch_size: int, elapsed_ms: float) -> None:
        events_per_sec = (batch_size / (elapsed_ms / 1000.0)) if elapsed_ms > 0 else 0.0
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO processing_metrics
                (source,batch_size,elapsed_ms,events_per_sec,created_at)
                VALUES (?,?,?,?,?)""",
                (source, batch_size, elapsed_ms, events_per_sec, _now()),
            )

    def latest_processing_metric(self, *, prefer_batch: bool = False) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = None
            if prefer_batch:
                row = conn.execute(
                    "SELECT * FROM processing_metrics WHERE batch_size > 1 ORDER BY id DESC LIMIT 1"
                ).fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT * FROM processing_metrics ORDER BY id DESC LIMIT 1"
                ).fetchone()
        return dict(row) if row else None

    def overview(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM raw_events").fetchone()["c"]
            parsed = conn.execute("SELECT COUNT(*) AS c FROM normalized_events").fetchone()["c"]
            failed = conn.execute("SELECT COUNT(*) AS c FROM quarantine").fetchone()["c"]
            rows = conn.execute("SELECT normalized_json FROM normalized_events").fetchall()
        vendor_distribution: dict[str, int] = {}
        action_distribution: dict[str, int] = {}
        category_distribution: dict[str, int] = {}
        for row in rows:
            event = json.loads(row["normalized_json"])
            vendor = event.get("observer", {}).get("vendor") or "Unknown"
            action = event.get("event", {}).get("action") or "UNKNOWN"
            category = event.get("event", {}).get("category") or "UNKNOWN"
            vendor_distribution[vendor] = vendor_distribution.get(vendor, 0) + 1
            action_distribution[action] = action_distribution.get(action, 0) + 1
            category_distribution[category] = category_distribution.get(category, 0) + 1
        return {
            "total_events": total,
            "parsed_events": parsed,
            "unknown_failed": failed,
            "vendor_distribution": vendor_distribution,
            "action_distribution": action_distribution,
            "category_distribution": category_distribution,
            "latest_throughput": self.latest_processing_metric(prefer_batch=True),
        }

    def save_onboarding_draft(
        self,
        *,
        plugin_id: str,
        vendor: str,
        product: str,
        payload: str,
        analysis: dict[str, Any],
        mappings: dict[str, str],
        preview: dict[str, Any],
    ) -> dict[str, Any]:
        draft_id = f"draft_{uuid4().hex}"
        created_at = _now()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO onboarding_drafts
                (draft_id,plugin_id,vendor,product,payload,analysis_json,mappings_json,preview_json,status,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    draft_id,
                    plugin_id,
                    vendor,
                    product,
                    payload,
                    json.dumps(analysis, sort_keys=True),
                    json.dumps(mappings, sort_keys=True),
                    json.dumps(preview, sort_keys=True),
                    "DRAFT_REVIEW_REQUIRED",
                    created_at,
                ),
            )
        return {
            "draft_id": draft_id,
            "plugin_id": plugin_id,
            "status": "DRAFT_REVIEW_REQUIRED",
            "created_at": created_at,
            "auto_activated": False,
        }

    def get_onboarding_draft(self, draft_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM onboarding_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["analysis"] = json.loads(item.pop("analysis_json"))
        item["mappings"] = json.loads(item.pop("mappings_json"))
        item["preview"] = json.loads(item.pop("preview_json"))
        return item

    def update_onboarding_draft_status(self, draft_id: str, status: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE onboarding_drafts SET status=? WHERE draft_id=?", (status, draft_id)
            )

    def list_onboarding_drafts(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT draft_id,plugin_id,vendor,product,status,created_at
                   FROM onboarding_drafts ORDER BY created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_audit(
        self,
        *,
        actor: str,
        action: str,
        object_type: str,
        object_id: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        created_at = _now()
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO audit_log
                (actor,action,object_type,object_id,details_json,created_at) VALUES (?,?,?,?,?,?)""",
                (actor, action, object_type, object_id, json.dumps(details or {}, sort_keys=True), created_at),
            )
            audit_id = cur.lastrowid
        return {
            "id": audit_id,
            "actor": actor,
            "action": action,
            "object_type": object_type,
            "object_id": object_id,
            "details": details or {},
            "created_at": created_at,
        }

    def list_audit(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            output.append(item)
        return output

    def export_events(self, limit: int = 10000) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT normalized_json FROM normalized_events ORDER BY created_at ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row["normalized_json"]) for row in rows]

    def count_raw_events(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) AS c FROM raw_events").fetchone()["c"])
