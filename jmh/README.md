# JMH Benchmarks

This directory contains JMH (Java Microbenchmark Harness) benchmarks for the card fraud rule engine.

## Running Benchmarks

### Run all benchmarks
```bash
mvn clean install -Pjmh
java -jar target/benchmarks.jar
```

### Run specific benchmark
```bash
java -jar target/benchmarks.jar ".*RuleEvaluationBenchmark.*"
```

### Run with warmup and measurement control
```bash
java -jar target/benchmarks.jar -wi 5 -i 5 -f 2
```

## Benchmark Descriptions

| Benchmark | Description |
|----------|-------------|
| `benchmarkInterpretiveCondition` | Original HashMap + Stream-based condition evaluation |
| `benchmarkCompiledCondition` | Lambda-compiled condition with direct array access |
| `benchmarkHashMapLookup` | HashMap.get() field lookup |
| `benchmarkArrayAccess` | Direct array access via field ID |
| `benchmarkCreateHashMap` | Creating new HashMap from TransactionContext |
| `benchmarkMultipleRulesInterpretive` | Evaluate 10 rules using original approach |
| `benchmarkMultipleRulesCompiled` | Evaluate 10 rules using compiled approach |
| `benchmarkGetRulesByPriority` | Sorting rules by priority (tests caching) |

## Expected Results

| Operation | Expected Time (microseconds) |
|-----------|---------------------------|
| Single condition (interpretive) | ~1-2 µs |
| Single condition (compiled) | ~0.1-0.5 µs |
| HashMap lookup | ~0.1 µs |
| Array access | ~0.01 µs |
| HashMap creation (15 fields) | ~2-3 µs |
| 10 rules evaluation | ~10-20 µs |

## Interpreting Results

- **Score**: Average time per operation (lower is better)
- **Error**: Standard deviation of measurements
- **Samples**: Number of iterations performed

Compare:
1. `benchmarkInterpretiveCondition` vs `benchmarkCompiledCondition` - should see 5-10x improvement
2. `benchmarkHashMapLookup` vs `benchmarkArrayAccess` - should see 10x improvement
3. `benchmarkMultipleRulesInterpretive` vs `benchmarkMultipleRulesCompiled` - should see 2-3x improvement
