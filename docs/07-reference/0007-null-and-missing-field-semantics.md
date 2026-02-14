# ADR-0007: Null and Missing Field Semantics

**Status:** Accepted

## Context
Rule conditions reference fields in an incoming JSON payload. Implementations must agree on what happens when:
- a field is missing
- a field is present with a JSON `null` value
- nested field access encounters a missing parent
- a comparison is attempted on a null/missing value

Ambiguity here leads to inconsistent rule behavior across languages and runtimes.

## Decision
### Definitions
- **UNDEFINED**: field is missing (not present at the referenced path)
- **NULL**: field is present with JSON value `null`

UNDEFINED and NULL are **distinct**.

### Field resolution
- Resolving `payload.foo.bar`:
  - if `foo` is UNDEFINED → result is UNDEFINED
  - if `foo` is NULL → result is UNDEFINED

### Operator semantics
- `exists(field)`:
  - field is UNDEFINED → `false`
  - field is NULL → `true`

- Comparisons (`eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, string ops):
  - if the resolved field value is UNDEFINED → result is `false` (NON-MATCH)
  - if the resolved field value is NULL → result is `false` (NON-MATCH)

### Type coercion
- No implicit coercion.
- If field type does not match the operator’s expected type, the operator result is `false` (NON-MATCH).

## Rationale
- Keeps evaluation total (never throws due to missing/null).
- Avoids surprising matches based on null/missing values.
- Makes rule behavior consistent and easy to reason about.

## Consequences
- Rules cannot explicitly match NULL values in v1 (by design).
- If null-matching becomes a requirement, introduce explicit operators (e.g., `is_null`) in a future schema_version.

## Notes
This ADR intentionally favors safety and predictability over expressiveness for v1.
