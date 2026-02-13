package com.fraud.engine.benchmark;

import com.fraud.engine.domain.Condition;
import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.Rule;
import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.domain.compiled.CompiledCondition;
import com.fraud.engine.domain.compiled.CompiledRule;
import com.fraud.engine.domain.compiled.CompiledRuleset;
import com.fraud.engine.engine.ConditionCompiler;
import com.fraud.engine.engine.RuleEvaluator;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * JMH benchmarks for rule evaluation performance.
 * <p>
 * Measures the performance of:
 * <ul>
 *   <li>Interpretive condition evaluation (original implementation)</li>
 *   *   *   <li>Compiled condition evaluation (lambda-based)</li>
 *     *   *   <li>Array-based field access vs HashMap lookup</li>
 *   *   *   <li>For-loop vs Stream API</li>
 * </ul>
 * <p>
 * Run with: mvn clean install && java -jar target/benchmarks.jar
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(2)
@State(Scope.Benchmark)
public class RuleEvaluationBenchmark {

    // ========== Benchmark State ==========

    /**
     * Setup for interpretive evaluation (original implementation).
     */
    @State(Scope.Benchmark)
    public static class InterpretiveState {
        private Rule rule;
        private Map<String, Object> context;
        private TransactionContext transaction;

        @Setup(Level.Trial)
        public void setup() {
            // Create a rule with 3 conditions
            rule = new Rule("test-rule", "Test Rule", "DECLINE");
            rule.setPriority(100);
            rule.setEnabled(true);
            rule.addCondition(new Condition("amount", "gt", 100));
            rule.addCondition(new Condition("country_code", "eq", "US"));
            rule.addCondition(new Condition("merchant_category", "ne", "Gambling"));

            // Create context map (traditional approach)
            context = new HashMap<>(32);
            context.put("amount", BigDecimal.valueOf(150.00));
            context.put("currency", "USD");
            context.put("country_code", "US");
            context.put("merchant_id", "merch-001");
            context.put("merchant_category", "Retail");

            // Create transaction
            transaction = new TransactionContext();
            transaction.setTransactionId("txn-123");
            transaction.setCardHash("abc123");
            transaction.setAmount(BigDecimal.valueOf(150.00));
            transaction.setCurrency("USD");
            transaction.setCountryCode("US");
            transaction.setMerchantId("merch-001");
            transaction.setMerchantCategory("Retail");
        }
    }

    /**
     * Setup for compiled evaluation (lambda-based).
     */
    @State(Scope.Benchmark)
    public static class CompiledState {
        private CompiledRule compiledRule;
        private TransactionContext transaction;

        @Setup(Level.Trial)
        public void setup() {
            // Create conditions
            List<Condition> conditions = new ArrayList<>();
            conditions.add(new Condition("amount", "gt", 100));
            conditions.add(new Condition("country_code", "eq", "US"));
            conditions.add(new Condition("merchant_category", "ne", "Gambling"));

            // Compile conditions
            CompiledCondition compiledCondition = ConditionCompiler.compileAll(conditions);

            compiledRule = new CompiledRule(
                "test-rule",
                "Test Rule",
                "DECLINE",
                100,
                true,
                compiledCondition,
                null
            );

            // Create transaction
            transaction = new TransactionContext();
            transaction.setTransactionId("txn-123");
            transaction.setCardHash("abc123");
            transaction.setAmount(BigDecimal.valueOf(150.00));
            transaction.setCurrency("USD");
            transaction.setCountryCode("US");
            transaction.setMerchantId("merch-001");
            transaction.setMerchantCategory("Retail");
        }
    }

    /**
     * Setup for HashMap vs Array comparison.
     */
    @State(Scope.Benchmark)
    public static class FieldAccessState {
        private TransactionContext transaction;
        private Map<String, Object> hashMapContext;

        @Setup(Level.Trial)
        public void setup() {
            transaction = new TransactionContext();
            transaction.setTransactionId("txn-123");
            transaction.setCardHash("abc123");
            transaction.setAmount(BigDecimal.valueOf(150.00));
            transaction.setCurrency("USD");
            transaction.setCountryCode("US");

            // Traditional HashMap context
            hashMapContext = new HashMap<>(32);
            hashMapContext.put("transaction_id", "txn-123");
            hashMapContext.put("card_hash", "abc123");
            hashMapContext.put("amount", BigDecimal.valueOf(150.00));
            hashMapContext.put("currency", "USD");
            hashMapContext.put("country_code", "US");
        }
    }

    // ========== Benchmarks: Condition Evaluation ==========

    @Benchmark
    public boolean benchmarkInterpretiveCondition(InterpretiveState state) {
        return state.rule.matches(state.context);
    }

    @Benchmark
    public boolean benchmarkCompiledCondition(CompiledState state) {
        return state.compiledRule.matches(state.transaction);
    }

    // ========== Benchmarks: Field Access ==========

    @Benchmark
    public Object benchmarkHashMapLookup(FieldAccessState state) {
        return state.hashMapContext.get("amount");
    }

    @Benchmark
    public Object benchmarkArrayAccess(FieldAccessState state) {
        return state.transaction.getField(TransactionContext.F_AMOUNT);
    }

    // ========== Benchmarks: HashMap Creation ==========

    @Benchmark
    public Map<String, Object> benchmarkCreateHashMap(FieldAccessState state) {
        return state.transaction.toEvaluationContext();
    }

    // ========== Benchmarks: Multiple Rules ==========

    /**
     * State for multi-rule evaluation.
     */
    @State(Scope.Benchmark)
    public static class MultiRuleState {
        private List<Rule> interpretiveRules;
        private List<CompiledRule> compiledRules;
        private Map<String, Object> context;
        private TransactionContext transaction;

        @Setup(Level.Trial)
        public void setup() {
            interpretiveRules = new ArrayList<>();
            compiledRules = new ArrayList<>();

            // Create 10 rules with varying conditions
            for (int i = 0; i < 10; i++) {
                Rule rule = new Rule("rule-" + i, "Rule " + i, i % 2 == 0 ? "DECLINE" : "APPROVE");
                rule.setPriority(100 - i);
                rule.setEnabled(true);
                rule.addCondition(new Condition("amount", "gt", i * 10));

                List<Condition> conditions = new ArrayList<>();
                conditions.add(new Condition("amount", "gt", i * 10));
                CompiledCondition compiled = ConditionCompiler.compileAll(conditions);

                CompiledRule compiledRule = new CompiledRule(
                    "rule-" + i,
                    "Rule " + i,
                    i % 2 == 0 ? "DECLINE" : "APPROVE",
                    100 - i,
                    true,
                    compiled,
                    null
                );

                interpretiveRules.add(rule);
                compiledRules.add(compiledRule);
            }

            context = new HashMap<>(32);
            context.put("amount", BigDecimal.valueOf(150.00));
            context.put("currency", "USD");

            transaction = new TransactionContext();
            transaction.setAmount(BigDecimal.valueOf(150.00));
            transaction.setCurrency("USD");
        }
    }

    @Benchmark
    public boolean benchmarkMultipleRulesInterpretive(MultiRuleState state) {
        for (Rule rule : state.interpretiveRules) {
            if (rule.matches(state.context)) {
                return true;
            }
        }
        return false;
    }

    @Benchmark
    public boolean benchmarkMultipleRulesCompiled(MultiRuleState state) {
        for (CompiledRule rule : state.compiledRules) {
            if (rule.matches(state.transaction)) {
                return true;
            }
        }
        return false;
    }

    // ========== Benchmarks: String Comparison ==========

    @State(Scope.Benchmark)
    public static class StringComparisonState {
        private String value1 = "amount";
        private String value2 = "country_code";
        private String value3 = "merchant_id";

        @CompilerControl(CompilerControl.Mode.DONT_INLINE)
        public static boolean equalsIgnoreCase(String s1, String s2) {
            return s1.equalsIgnoreCase(s2);
        }
    }

    @Benchmark
    public boolean benchmarkStringEquals(StringComparisonState state) {
        return "amount".equals(state.value1);
    }

    @Benchmark
    public boolean benchmarkStringEqualsIgnoreCase(StringComparisonState state) {
        return equalsIgnoreCase("AMOUNT", state.value1);
    }

    // ========== Benchmarks: Operator Switch ==========

    @State(Scope.Benchmark)
    public static class OperatorState {
        private static final String OP_GT = "gt";
        private static final String OP_GTE = "gte";
        private static final String OP_LT = "lt";
        private static final String OP_LTE = "lte";
        private static final String OP_EQ = "eq";

        private String operator = "gt";
    }

    @Benchmark
    public int benchmarkStringSwitch(OperatorState state) {
        return switch (state.operator.toLowerCase()) {
            case "gt" -> 1;
            case "gte" -> 2;
            case "lt" -> 3;
            case "lte" -> 4;
            case "eq" -> 5;
            default -> 0;
        };
    }

    @Benchmark
    public int benchmarkIntSwitch(OperatorState state) {
        int opCode = switch (state.operator) {
            case "gt" -> 1;
            case "gte" -> 2;
            case "lt" -> 3;
            case "lte" -> 4;
            case "eq" -> 5;
            default -> 0;
        };
        return opCode;
    }

    // ========== Benchmarks: Ruleset Sorting ==========

    @State(Scope.Benchmark)
    public static class RulesetState {
        private Ruleset ruleset;

        @Setup(Level.Trial)
        public void setup() {
            ruleset = new Ruleset("TEST", 1);
            // Add 50 rules in random priority order
            for (int i = 0; i < 50; i++) {
                Rule rule = new Rule("rule-" + i, "Rule " + i, "APPROVE");
                rule.setPriority((int) (Math.random() * 100));
                rule.setEnabled(i % 2 == 0); // 50% enabled
                ruleset.addRule(rule);
            }
        }
    }

    @Benchmark
    public List<Rule> benchmarkGetRulesByPriority(RulesetState state) {
        return state.ruleset.getRulesByPriority();
    }

    // ========== Benchmarks: Context Creation ==========

    @Benchmark
    public TransactionContext benchmarkCreateTransaction() {
        return new TransactionContext();
    }

    @Benchmark
    public Map<String, Object> benchmarkCreateContextMap() {
        Map<String, Object> context = new HashMap<>(32);
        context.put("transaction_id", "txn-123");
        context.put("card_hash", "abc123");
        context.put("amount", BigDecimal.valueOf(150.00));
        context.put("currency", "USD");
        context.put("country_code", "US");
        context.put("merchant_id", "merch-001");
        context.put("merchant_category", "Retail");
        context.put("ip_address", "192.168.1.1");
        context.put("device_id", "device-123");
        context.put("email", "user@example.com");
        return context;
    }
}
