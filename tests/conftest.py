from __future__ import annotations

from pathlib import Path

import pytest

from ulpf.pipeline import CoreEngine
from ulpf.registry import PluginRegistry
from ulpf.storage import SQLiteStore


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "plugins" / "fortigate" / "fixtures"


@pytest.fixture()
def engine(tmp_path: Path) -> CoreEngine:
    store = SQLiteStore(tmp_path / "test.db")
    registry = PluginRegistry(ROOT / "plugins")
    return CoreEngine(store, registry)


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8").rstrip("\n")

DATASETS = ROOT / "datasets"


def read_dataset(relative: str) -> str:
    return (DATASETS / relative).read_text(encoding="utf-8").rstrip("\n")
