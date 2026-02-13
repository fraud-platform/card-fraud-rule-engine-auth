# Next Optimization Strategies (ChatGPT Analysis)

## Current State (2026-02-08)

**Performance:**
- AUTH P50: 83ms (target: <5ms) - **16x gap**
- AUTH P95: 160ms (target: <10ms) - **16x gap**
- JFR Analysis: Jackson consuming 27.5% of CPU

**What We've Tried:**
1. ✅ Jackson Blackbird - 20-30% improvement
2. ✅ Slim AuthResult DTO - 10-15x smaller response
3. ✅ Remove transactionContext from AUTH - Reduced payload
4. ❌ jsoniter - Java 17 module incompatibility
5. ❌ ZGC - Made performance worse (small heap issue)
6. ✅ Pool increases - 23% improvement

**Verdict:** "We are parsing far more than AUTH needs" 🎯

---

## Concrete Strategies (Ranked by Impact)

### ✅ 1. Partial Parsing / Field Projection (HIGHEST IMPACT)

**Problem:** AUTH path deserializes entire request into full POJO graph, but only needs 10-15 fields for rule evaluation.

**Solution:** Use Jackson streaming API to extract only AUTH-required fields

**Expected Impact:** 20-30ms reduction (from ~50ms to ~20-30ms)

**Implementation:**
```java
// Instead of:
TransactionRequest request = objectMapper.readValue(body, TransactionRequest.class);

// Do this for AUTH:
JsonParser parser = jsonFactory.createParser(body);
AuthView view = new AuthView();  // Tiny struct with only AUTH fields
while (parser.nextToken() != null) {
    switch (parser.currentName()) {
        case "amount" -> view.amount = parser.getValueAsDouble();
        case "mcc" -> view.mcc = parser.getValueAsString();
        case "panHash" -> view.panHash = parser.getValueAsString();
        // ... only the 10-15 fields AUTH rules need
    }
}
```

**Codebase Impact:**
- `EvaluationResource.java`: Add streaming parser path for AUTH
- `AuthEvaluator.java`: Accept `AuthView` instead of full `TransactionRequest`
- `MonitoringEvaluator.java`: Keep full deserialization (needs all fields)

**Files to check for required fields:**
```bash
grep -r "transaction\." src/main/resources/rulesets/  # Find all fields referenced by rules
```

---

### ✅ 2. Two-Track Representation (HIGH IMPACT)

**Problem:** We deserialize twice: HTTP → POJO, then POJO → Redis JSON

**Solution:**
1. Keep raw request `byte[]` throughout AUTH path
2. Extract tiny `AuthView` struct via streaming parser
3. Store raw bytes in Redis (not re-serialized JSON)
4. Only do full deserialization for MONITORING path

**Expected Impact:** 10-15ms reduction (eliminates double serialization)

**Implementation:**
```java
@Path("/v1/evaluate")
public class EvaluationResource {

    @POST
    @Path("/auth")
    public Response evaluateAuth(byte[] rawBody) {  // Keep as bytes!
        // 1. Stream-parse only AUTH fields
        AuthView view = streamingParser.parseAuthView(rawBody);

        // 2. Evaluate rules using AuthView
        Decision decision = authEvaluator.evaluate(view);

        // 3. Store rawBody in Redis outbox (NOT re-serialized)
        outboxClient.publish(decision.decisionId, rawBody);

        // 4. Return slim AuthResult
        return Response.ok(new AuthResult(decision));
    }
}
```

**Codebase Impact:**
- `EvaluationResource.java`: Accept `byte[]` instead of POJO
- `RedisStreamsOutboxClient.java`: Store raw bytes directly
- `MonitoringOutboxWorker.java`: Deserialize bytes → full POJO for MONITORING eval

---

### ✅ 3. Precompiled Rule Field Access (MEDIUM IMPACT)

**Problem:** Rules use MVEL/OGNL to access fields like `transaction.amount`, which uses reflection

**Current Approach:**
```java
// MVEL compiles and caches expressions, but still uses reflection
CompiledExpression expr = MVEL.compileExpression("transaction.amount > 1000");
```

**Better Approach:** Precompile JSON paths into streaming extractors

**Expected Impact:** 5-10ms reduction (eliminates reflection overhead)

**Implementation:**
```java
// Compile rules to use direct field access
public class CompiledRule {
    private final Function<AuthView, Object> fieldAccessor;  // No reflection!

    public boolean evaluate(AuthView view) {
        double amount = (double) fieldAccessor.apply(view);  // Direct field access
        return amount > 1000;
    }
}
```

**Codebase Impact:**
- `CompiledCondition.java`: Add field accessor compilation
- `RuleCompiler.java`: Generate direct accessors instead of MVEL expressions
- May require custom DSL for simple rules (e.g., `amount > 1000 AND mcc = '5411'`)

**Trade-off:** More complex rule compilation, but 10x faster evaluation

---

### ✅ 4. Reuse Buffers + Zero-Copy (MEDIUM IMPACT)

**Problem:** Quarkus/Vert.x allocates new byte arrays for each request

**Solution:**
- Use Netty `ByteBuf` slices (zero-copy)
- Pass `ByteBuf` to streaming parser (no `byte[]` conversion)
- Pool buffer allocators

**Expected Impact:** 3-5ms reduction (eliminates memory allocations)

**Implementation:**
```java
@POST
@Path("/auth")
public Response evaluateAuth(ByteBuf bodyBuf) {  // Zero-copy!
    // Parse directly from ByteBuf (no byte[] copy)
    AuthView view = streamingParser.parseAuthView(bodyBuf);
    // ...
}
```

**Codebase Impact:**
- `EvaluationResource.java`: Accept `ByteBuf` instead of `byte[]`
- May require Vert.x-specific handler (Quarkus RESTEasy might not support this)

**Warning:** Complex Quarkus integration - may not be worth the effort

---

### ✅ 5. GC Pressure Reduction (LOW-MEDIUM IMPACT)

**Already Tried:**
- ❌ ZGC - Made performance worse (small heap, short-lived objects)
- ✅ AlwaysPreTouch - 5% improvement

**Additional Options:**
- **Shenandoah GC** (Java 21) - Similar to ZGC but better for smaller heaps
- **Increase TLAB sizes** - `-XX:TLABSize=512k`
- **Reuse builders via ThreadLocal** - e.g., `ThreadLocal<StringBuilder>`

**Expected Impact:** 5-10ms reduction (more consistent P99)

**Implementation:**
```java
// Reuse expensive objects
private static final ThreadLocal<AuthView> VIEW_POOL =
    ThreadLocal.withInitial(AuthView::new);

public Decision evaluateAuth(byte[] body) {
    AuthView view = VIEW_POOL.get();
    view.reset();  // Clear previous state
    streamingParser.parseInto(body, view);  // Reuse instance
    // ...
}
```

**Trade-off:** More complex memory management, potential for state leaks

---

### ✅ 6. No Gzip on Auth Path (LOW IMPACT)

**Current:** Quarkus may be compressing responses

**Solution:** Disable response compression for `/v1/evaluate/auth`

**Expected Impact:** 2-3ms reduction

**Implementation:**
```yaml
# application.yaml
quarkus:
  http:
    enable-compression: false  # Disable for auth path
```

---

### ✅ 7. Only Serialize Once (LOW IMPACT)

**Problem:** We serialize twice:
1. POJO → JSON for Redis
2. POJO → JSON for HTTP response

**Solution:** Already addressed by #2 (store raw bytes in Redis)

**Expected Impact:** Included in #2 estimate

---

## Recommended Implementation Order

### Phase 1: Quick Wins (1-2 days)
1. ✅ **Disable gzip** - 2min config change, 2-3ms gain
2. ✅ **Increase TLAB sizes** - 5min JVM flag, 2-5ms gain

### Phase 2: Partial Parsing (3-5 days) 🎯
3. ✅ **Streaming parser for AUTH** - 20-30ms gain (HIGHEST IMPACT)
   - Create `AuthView` struct with only required fields
   - Implement Jackson streaming parser
   - Update `AuthEvaluator` to accept `AuthView`

### Phase 3: Two-Track Representation (2-3 days)
4. ✅ **Store raw bytes in Redis** - 10-15ms gain
   - Keep `byte[]` throughout AUTH path
   - Update outbox to store raw bytes
   - Update worker to deserialize for MONITORING

### Phase 4: Advanced (1-2 weeks)
5. ⚠️ **Precompiled field accessors** - 5-10ms gain (complex)
6. ⚠️ **Zero-copy ByteBuf** - 3-5ms gain (Quarkus integration complexity)

---

## Expected Results

**Current:** P50=83ms, P95=160ms

**After Phase 1-2:** P50=40-50ms, P95=80-100ms (40-50% improvement)
**After Phase 3:** P50=25-35ms, P95=50-70ms (70% improvement)
**After Phase 4:** P50=15-25ms, P95=30-50ms (80% improvement)

**Target:** P50<5ms, P95<10ms - May require Phase 4 + hardware (more cores, faster Redis)

---

## Key Insight from ChatGPT 🎯

> "Your current profile screams: We are parsing far more than AUTH needs. That's the lever."

**Verdict:** Focus on Phases 1-2 first. Streaming parser alone will likely get us to P50~40ms, which is a **50% improvement** from current 83ms.

---

## Next Session Action Items

1. **Measure current deserialization time**
   - Add timing for Jackson readValue() in EvaluationResource
   - Confirm it's 20-30ms as JFR suggests

2. **Identify AUTH-required fields**
   ```bash
   grep -r "transaction\." src/main/resources/rulesets/
   ```

3. **Implement streaming parser POC**
   - Create `AuthView` struct
   - Implement Jackson streaming parser
   - Benchmark: stream-parse vs full deserialization

4. **Run load test with streaming parser**
   - Target: P50 < 50ms
   - If achieved, proceed to Phase 3

---

## References

- [Jackson Streaming API](https://github.com/FasterXML/jackson-core)
- [Zero-Copy Buffers in Netty](https://netty.io/wiki/reference-counted-objects.html)
- [JFR Analysis Results](./JFR-ANALYSIS-RESULTS.md)
- [Session 2026-02-08 JSON Optimization](./session-2026-02-08-json-optimization.md)
