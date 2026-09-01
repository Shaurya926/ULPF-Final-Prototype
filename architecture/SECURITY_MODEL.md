# Phase 4 Prototype Security Model

Implemented controls:

- exact raw payload preservation with SHA-256 integrity hash;
- payload/file/batch byte and count limits from environment variables;
- UTF-8-only file ingestion;
- plugin path traversal/symlink escape rejection and plugin file size limits;
- YAML safe loading and plugin contract validation;
- raw logs rendered with escaped/text-only browser sinks;
- onboarding suggestions never auto-activate;
- runtime plugin state changes and onboarding draft creation are audited;
- secrets/configuration are supplied through environment variables;
- unknown and malformed data fail closed into quarantine.

The prototype contains no API that executes uploaded log contents or arbitrary onboarding code.
