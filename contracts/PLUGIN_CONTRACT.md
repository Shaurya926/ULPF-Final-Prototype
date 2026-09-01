# ULPF Plugin Contract v0.1

Each adapter lives in its own directory under `plugins/` and must provide:

- `manifest.yaml`: plugin identity/version, vendor/product, format, enable flag, parser entrypoint, detection file, mapping file, required/optional fields.
- `detection.yaml`: deterministic source-identification evidence and confidence.
- `mappings.yaml`: universal-field mappings, casts, transforms, defaults, mapping version and extension namespace.
- `parser.py`: a source parser callable declared by the manifest.
- `fixtures/*.log`: sanitized regression inputs, including positive and negative cases.

The core registry discovers plugin directories dynamically. Core code contains no vendor-specific `if/elif` dispatch.

## Lossless rule

The raw payload is persisted before detection or parsing. Source attributes that are not consumed by universal mappings are copied into the plugin's `extensions.<plugin>` namespace. Every mapped field records source-field provenance.

## Safety rule

Detection, parsing, mapping or validation failures must quarantine the raw event with a reason rather than silently dropping it or producing an invalid normalized event.
