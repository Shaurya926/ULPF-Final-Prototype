from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventCore(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str
    type: str
    action: str | None = None
    severity: str | None = None
    outcome: str | None = None


class Endpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str | None = None
    port: int | None = None

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, value: str | None) -> str | None:
        if value is None:
            return value
        ip_address(value)
        return value

    @field_validator("port")
    @classmethod
    def valid_port(cls, value: int | None) -> int | None:
        if value is not None and not 0 <= value <= 65535:
            raise ValueError("port must be between 0 and 65535")
        return value


class Network(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transport: str | None = None
    application: str | None = None


class Observer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vendor: str
    product: str
    name: str | None = None


class RawReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str
    payload: str
    sha256: str


class FieldTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_field: str | list[str] | None = None
    transform: str | None = None
    cast: str | None = None
    default: bool | None = None


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    parser_id: str
    parser_version: str
    mapping_version: str
    detection_confidence: float
    detection_evidence: list[str]
    field_trace: dict[str, FieldTrace] = Field(default_factory=dict)


class UniversalEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    event_id: str
    timestamp: str = Field(alias="@timestamp")
    event: EventCore
    source: Endpoint = Field(default_factory=Endpoint)
    destination: Endpoint = Field(default_factory=Endpoint)
    network: Network = Field(default_factory=Network)
    observer: Observer
    extensions: dict[str, Any] = Field(default_factory=dict)
    raw: RawReference
    provenance: Provenance

    @field_validator("timestamp")
    @classmethod
    def valid_timestamp(cls, value: str) -> str:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("@timestamp must include timezone information")
        return value


class DetectionResult(BaseModel):
    plugin_id: str
    confidence: float
    evidence: list[str]


class DetectionAttempt(BaseModel):
    plugin_id: str
    matched: bool
    confidence: float
    evidence: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)


class ProcessResult(BaseModel):
    status: str
    raw_event_id: str
    event_id: str | None = None
    plugin_id: str | None = None
    reason: str | None = None
    detection_report: list[DetectionAttempt] | None = None
