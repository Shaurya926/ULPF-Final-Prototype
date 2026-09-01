# ULPF Phase 4 Air-Gap Runbook

The ULPF core has no CDN, remote API, or cloud dependency. Build the container image once on a connected machine, then the demo can be started with networking unavailable.

## 1. Prepare while connected

```bash
docker compose build
```

Optional: export the built image for transfer to an isolated machine:

```bash
docker save ulpf-sih2026:phase4 -o ulpf-sih2026-phase4.tar
```

On the isolated machine:

```bash
docker load -i ulpf-sih2026-phase4.tar
```

## 2. Disconnect internet / disable external network

Start without building or pulling:

```bash
docker compose up --no-build -d
```

Open `http://127.0.0.1:8000/`.

## 3. Demo proof

1. Load the five-vendor judge dataset.
2. Process all 10 events.
3. Inspect RAW → PARSED → NORMALIZED.
4. Export `/api/v1/export/ndjson`.
5. Stop the container:
   ```bash
   docker compose down
   ```
6. Start again:
   ```bash
   docker compose up --no-build -d
   ```
7. Verify events remain present. The named Docker volume `ulpf_data` preserves SQLite state.

## Local process-level verification

Without Docker, the same no-network persistence sequence can be verified with:

```bash
python scripts/airgap_check.py
```

This checks local startup, ingestion, normalization, inspection, export, reconstruction of the engine/store, and persistence from the same SQLite database.
