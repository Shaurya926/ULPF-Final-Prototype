from __future__ import annotations

import argparse
import json
from pathlib import Path

from .pipeline import CoreEngine
from .registry import PluginRegistry
from .storage import SQLiteStore


def build_engine(db: str, plugins: str) -> CoreEngine:
    return CoreEngine(SQLiteStore(db), PluginRegistry(plugins))


def main() -> None:
    parser = argparse.ArgumentParser(prog="ulpf")
    parser.add_argument("--db", default="data/ulpf.db")
    parser.add_argument("--plugins", default="plugins")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ingest = sub.add_parser("ingest")
    ingest.add_argument("file")

    inspect = sub.add_parser("inspect")
    inspect.add_argument("event_id")

    sub.add_parser("plugins")
    args = parser.parse_args()

    engine = build_engine(args.db, args.plugins)
    if args.cmd == "ingest":
        path = Path(args.file)
        results = engine.process_batch([line for line in path.read_text(encoding="utf-8").splitlines() if line])
        print(json.dumps([r.model_dump(mode="json") for r in results], indent=2))
    elif args.cmd == "inspect":
        print(json.dumps(engine.store.get_inspection(args.event_id), indent=2))
    elif args.cmd == "plugins":
        print(json.dumps(engine.registry.list_plugins(), indent=2))


if __name__ == "__main__":
    main()
