# ADR-0006: API Versioning Strategy

**Status:** Accepted

## Context
The runtime API is consumed by external callers and will evolve over time.

Without an explicit versioning strategy, breaking changes (field renames, semantic changes, endpoint changes) will be difficult to roll out safely and may force synchronized deploys across teams.

## Decision
Use **path-based versioning** with a `/v1/` prefix:
- `POST /v1/evaluate/auth`
- `POST /v1/evaluate/monitoring`

Compatibility rules:
- Adding new response fields is allowed within a version (consumers must ignore unknown fields).
- Breaking changes require a new major version (e.g., `/v2/...`).

## Rationale
- Simple, explicit, widely supported by tooling and gateways.
- Easy to run multiple versions concurrently.
- Enables stable, contract-testable interfaces.

## Consequences
- Documentation and OpenAPI specs must reflect the versioned paths.
- Future versions must be maintained intentionally (deprecation policy is a separate decision).
