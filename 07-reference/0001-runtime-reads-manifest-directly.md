# ADR-0001: Runtime Reads ruleset_manifest Directly (No Governance Read API)

**Status:** Superseded
**Superseded by:** ADR-0008

## Context
The runtime decision engine must load and hot-reload compiled rulesets. The authoritative index for the active ruleset is the governance (rule-management) database table `ruleset_manifest`.

## Decision
- The runtime reads the governance DB directly in **read-only mode**.
- The runtime is permitted to access **only** the `ruleset_manifest` table.
- There is **no** governance read API.
- The runtime has **no** interaction with transaction-management databases.
- The runtime uses Redis **only** for velocity counters.

## Rationale
- Avoids an extra hop and reduces startup/reload latency
- Avoids additional availability coupling and a separate service to secure/deploy
- Keeps the control-plane dependency simple: a single deterministic `SELECT`
- Improves local testing, replay, and debugging

## Consequences / Constraints
- Runtime DB principal must be strictly read-only and restricted to `ruleset_manifest`
- Runtime must fail fast on unexpected schema (defensive validation)
- Queries must be fixed/parameterized; no dynamic SQL

## Supersession Note
This ADR is retained for historical context only.

The active design is defined by ADR-0008, which removes runtime database access entirely and uses an S3-hosted `manifest.json` pointer file for ruleset discovery.
