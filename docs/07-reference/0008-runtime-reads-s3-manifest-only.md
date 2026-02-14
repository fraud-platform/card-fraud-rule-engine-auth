# ADR-0008: Runtime Reads S3 Manifest Only (No Database Access)

**Status:** Accepted
**Supersedes:** ADR-0001

## Context

The runtime decision engine must load and hot-reload compiled rulesets. The governance service (FastAPI) publishes versioned ruleset artifacts to S3 and maintains an audit trail in its own database.

ADR-0001 proposed that runtime read the governance database directly. This creates unnecessary coupling and complexity.

## Decision

- The runtime reads **only from S3** for ruleset discovery and loading.
- The runtime has **no database access** whatsoever.
- The runtime uses **Redis only** for velocity counters.
- Governance publishes a **manifest.json** file to S3 alongside versioned artifacts.
- Runtime polls the S3 manifest file to discover active ruleset versions.

## S3 Storage Layout

```
fraud-rulesets/
└── rulesets/
  └── {environment}/
    └── {ruleset_key}/
      ├── manifest.json           # Runtime source-of-truth pointer (written by governance)
      ├── v1/
      │   └── ruleset.json        # Immutable versioned artifact
      ├── v2/
      │   └── ruleset.json
      └── v3/
        └── ruleset.json
```

## Manifest File Format

```json
{
  "environment": "prod",
  "ruleset_key": "CARD_AUTH",
  "ruleset_version": 3,
  "artifact_uri": "s3://fraud-rulesets/rulesets/prod/CARD_AUTH/v3/ruleset.json",
  "checksum": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "schema_version": 1,
  "published_at": "2026-01-16T10:30:00Z",
  "published_by": "governance-service"
}
```

## Rationale

1. **Simpler Architecture** — Runtime has single external dependency (S3 + Redis)
2. **No Database Coupling** — Runtime never queries governance database
3. **Clear Ownership** — Governance owns publishing; runtime owns consumption
4. **Pull-Based** — Runtime pulls from S3; no push mechanism needed
5. **Environment Parity** — Same S3 SDK for local (MinIO) and production (AWS)
6. **Audit in Governance** — Governance DB manifest table serves audit purposes only

## Consequences / Constraints

- Governance must write `manifest.json` to S3 on every publish
- Runtime polls S3 manifest file (not S3 listing)
- S3 must be highly available (use regional/multi-AZ)
- Runtime startup fails if S3 unreachable (fail-fast, not fail-open for startup)
- Hot-reload continues with cached ruleset if S3 temporarily unavailable

## Runtime External Dependencies

| Dependency | Purpose |
|------------|---------|
| **S3** | Manifest file + ruleset artifacts |
| **Redis** | Velocity counters only |

No other external systems are accessed by runtime.

## Migration from ADR-0001

1. Governance service must be updated to write `manifest.json` to S3
2. Runtime removes all database configuration and code
3. Runtime implements S3 manifest polling
4. ADR-0001 is superseded and should be marked as such
