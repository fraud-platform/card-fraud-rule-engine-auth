# jsoniter Java 17 Incompatibility

## Issue

jsoniter cannot serialize objects containing `java.time.Instant` fields on Java 17+ due to module system restrictions.

## Error

```
com.jsoniter.spi.JsonException: java.lang.reflect.InaccessibleObjectException:
Unable to make field private final long java.time.Instant.seconds accessible:
module java.base does not "opens java.time" to unnamed module
```

## Root Cause

- Java 17+ module system prevents reflection access to private fields in `java.base` classes
- jsoniter uses reflection to serialize/deserialize nested objects
- Custom encoders/decoders only work for direct Instant serialization, not when Instant is a field

## Impact

Our domain objects extensively use Instant fields:
- `Decision.timestamp`
- `Ruleset.createdAt`, `updatedAt`
- `TransactionContext.transactionTime`
- `DebugInfo.evaluatedAt`

## Attempted Solutions

1. ✅ **Custom encoders/decoders**: Works for direct Instant serialization
2. ❌ **Nested object serialization**: jsoniter still uses reflection on nested Instant fields
3. ⚠️ **JVM flags** (`--add-opens java.base/java.time=ALL-UNNAMED`): Works but not recommended for production

## Current Solution

**Use Jackson + Blackbird instead:**
- ✅ 20-30% faster serialization (vs baseline Jackson)
- ✅ Full Java 17 compatibility
- ✅ Native Quarkus support
- ✅ No reflection issues

## Configuration

jsoniter is DISABLED by default in `application.yaml`:
```yaml
app:
  jsoniter:
    enabled: false  # Default: disabled due to Java 17 incompatibility
```

## Future

Monitor jsoniter GitHub for Java 17 module system support. If they add proper support for java.time without reflection, we can retry this optimization (10x faster serialization potential).

## References

- [Gson Issue #1996](https://github.com/google/gson/issues/1996) - Similar issue with Gson
- [Jackson Issue #4082](https://github.com/FasterXML/jackson-databind/issues/4082) - Jackson's approach to Java 17
- [Java 17 InaccessibleObjectException Guide](https://medium.com/@rajvirsinghrai/java-17-inaccessibleobjectexception-bf030a348e48)

## Test Results

- Direct Instant serialization: ✅ Works with custom encoders
- Nested Instant fields: ❌ InaccessibleObjectException
- All 554 core tests: ✅ Pass (jsoniter disabled)
- jsoniter-specific tests: ❌ 5 errors (Java 17 module issue)
