# Phase 4 Scale Architecture

Target production topology:

`Ingress → bounded queue → stateless normalization workers → normalized output`

The Phase 4 prototype deliberately benchmarks the deterministic single-process engine first. The core engine is already stateless with respect to parser logic: worker state is plugin configuration plus storage/output handles. A production deployment can place a durable queue (for example Kafka-compatible infrastructure) ahead of multiple identical workers and route normalized output to a database/search/data-lake sink.

## Backpressure and safety

- ingress enforces event, file, batch-count, and batch-byte limits;
- a bounded queue prevents unbounded memory growth;
- unknown/malformed events go to quarantine instead of retry loops;
- workers do not execute log contents;
- plugin definitions are validated before loading;
- deterministic known-source parsing stays independent from optional authoring assistance.

## Claim boundary

The repository's benchmark is a **single-process local baseline**. It supports the statement **“horizontally scalable architecture”** because the worker boundary is separable; it does not justify billion-event/day production claims.
