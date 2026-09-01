from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ulpf.pipeline import CoreEngine
from ulpf.registry import PluginRegistry
from ulpf.storage import SQLiteStore


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = (len(ordered) - 1) * q
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    if lo == hi:
        return ordered[lo]
    frac = idx - lo
    return ordered[lo] * (1 - frac) + ordered[hi] * frac


def rss_mb() -> float:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB, macOS reports bytes.
    if platform.system() == "Darwin":
        return value / (1024 * 1024)
    return value / 1024


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproducible local ULPF engine benchmark")
    parser.add_argument("--events", type=int, default=500, help="Number of valid synthetic events")
    parser.add_argument("--output", default=str(ROOT / "reports" / "phase4_benchmark.json"))
    args = parser.parse_args()
    if args.events <= 0:
        raise SystemExit("--events must be positive")

    corpus = [line for line in (ROOT / "datasets" / "judge_demo.log").read_text(encoding="utf-8").splitlines() if line.strip()]
    payloads = [corpus[i % len(corpus)] for i in range(args.events)]

    with tempfile.TemporaryDirectory(prefix="ulpf-benchmark-") as tmp:
        db_path = Path(tmp) / "benchmark.db"
        engine = CoreEngine(SQLiteStore(db_path), PluginRegistry(ROOT / "plugins"))
        latencies_ms: list[float] = []
        failures = 0
        rss_before = rss_mb()
        started = time.perf_counter()
        for payload in payloads:
            t0 = time.perf_counter()
            result = engine.process(payload)
            latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            if result.status != "STORED":
                failures += 1
        duration_s = time.perf_counter() - started
        rss_after = rss_mb()

    report = {
        "benchmark_name": "ULPF Phase 4 single-process engine baseline",
        "dataset": "datasets/judge_demo.log repeated round-robin; synthetic telemetry",
        "events": args.events,
        "stored": args.events - failures,
        "failures": failures,
        "failure_rate": failures / args.events,
        "batch_duration_s": duration_s,
        "events_per_sec": args.events / duration_s if duration_s else 0.0,
        "latency_ms": {
            "p50": percentile(latencies_ms, 0.50),
            "p95": percentile(latencies_ms, 0.95),
            "mean": statistics.fmean(latencies_ms),
            "min": min(latencies_ms),
            "max": max(latencies_ms),
        },
        "memory_mb": {
            "process_max_rss_before": rss_before,
            "process_max_rss_after": rss_after,
            "max_rss_delta": max(0.0, rss_after - rss_before),
        },
        "hardware": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or "unknown",
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
        },
        "methodology": {
            "path": "CoreEngine.process -> SQLiteStore",
            "concurrency": 1,
            "network_included": False,
            "http_included": False,
            "warmup_excluded": False,
            "claim_scope": "local prototype baseline only; not production-scale throughput",
        },
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md = output.with_suffix(".md")
    md.write_text(
        "# ULPF Phase 4 Benchmark\n\n"
        "> Synthetic fixed-corpus local benchmark. These numbers are not production claims.\n\n"
        f"- Events: **{report['events']}**\n"
        f"- Stored: **{report['stored']}**\n"
        f"- Failures: **{report['failures']}** ({report['failure_rate']:.2%})\n"
        f"- Throughput: **{report['events_per_sec']:.2f} events/sec**\n"
        f"- Batch duration: **{report['batch_duration_s']:.3f} s**\n"
        f"- p50 latency: **{report['latency_ms']['p50']:.3f} ms**\n"
        f"- p95 latency: **{report['latency_ms']['p95']:.3f} ms**\n"
        f"- Max RSS after: **{report['memory_mb']['process_max_rss_after']:.2f} MiB**\n"
        f"- CPU count reported by runtime: **{report['hardware']['cpu_count']}**\n\n"
        "Method: single-process deterministic engine + SQLite, HTTP/network excluded.\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
