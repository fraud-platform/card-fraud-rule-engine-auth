package com.fraud.engine.engine;

import com.fraud.engine.domain.CompiledCondition;
import com.fraud.engine.domain.Condition;
import com.fraud.engine.domain.TransactionContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for ConditionCompiler - compiles conditions into executable lambdas.
 */
class ConditionCompilerTest {

    private TransactionContext transaction;

    @BeforeEach
    void setUp() {
        transaction = new TransactionContext();
        transaction.setTransactionId("txn-123");
        transaction.setCardHash("abc123");
        transaction.setAmount(BigDecimal.valueOf(150.00));
        transaction.setCurrency("USD");
        transaction.setCountryCode("US");
        transaction.setMerchantId("merch-001");
        transaction.setMerchantCategory("Retail");
        transaction.setIpAddress("192.168.1.1");
        transaction.setDeviceId("device-123");
        transaction.setEmail("user@example.com");
    }

    // ===== Comparison Operators =====

    @Test
    void testCompileGreaterThan() {
        Condition condition = new Condition("amount", "gt", 100);
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setAmount(BigDecimal.valueOf(100));
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileGreaterThanOrEqual() {
        Condition condition = new Condition("amount", "gte", 100);
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setAmount(BigDecimal.valueOf(100));
        assertThat(compiled.matches(transaction)).isTrue(); // Boundary

        transaction.setAmount(BigDecimal.valueOf(99));
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileLessThan() {
        Condition condition = new Condition("amount", "lt", 200);
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setAmount(BigDecimal.valueOf(200));
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileLessThanOrEqual() {
        Condition condition = new Condition("amount", "lte", 150);
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setAmount(BigDecimal.valueOf(150));
        assertThat(compiled.matches(transaction)).isTrue(); // Boundary

        transaction.setAmount(BigDecimal.valueOf(151));
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileEquals() {
        Condition condition = new Condition("country_code", "eq", "US");
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setCountryCode("UK");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileNotEquals() {
        Condition condition = new Condition("country_code", "ne", "UK");
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setCountryCode("UK");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    // ===== String Operators =====

    @Test
    void testCompileContains() {
        transaction.setMerchantName("Amazon Web Services");
        Condition condition = new Condition("merchant_name", "contains", "Amazon");
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setMerchantName("Walmart");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileStartsWith() {
        transaction.setCardHash("abc123xyz");
        Condition condition = new Condition("card_hash", "starts_with", "abc");
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setCardHash("xyzabc");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileEndsWith() {
        transaction.setCardHash("abc123xyz");
        Condition condition = new Condition("card_hash", "ends_with", "xyz");
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setCardHash("abc123xy");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileRegex() {
        transaction.setEmail("user@example.com");
        Condition condition = new Condition("email", "regex", ".*@example\\.com$");
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setEmail("user@other.com");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    // ===== List Operators =====

    @Test
    void testCompileIn() {
        Condition condition = new Condition();
        condition.setField("country_code");
        condition.setOperator("in");
        condition.setValues(List.of("US", "CA", "UK"));

        CompiledCondition compiled = ConditionCompiler.compile(condition);

        transaction.setCountryCode("US");
        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setCountryCode("DE");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileNotIn() {
        Condition condition = new Condition();
        condition.setField("country_code");
        condition.setOperator("not_in");
        condition.setValues(List.of("US", "CA", "UK"));

        CompiledCondition compiled = ConditionCompiler.compile(condition);

        transaction.setCountryCode("DE");
        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setCountryCode("US");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    // ===== Multiple Conditions (AND logic) =====

    @Test
    void testCompileAll_MultipleConditions() {
        List<Condition> conditions = List.of(
            new Condition("amount", "gt", 100),
            new Condition("country_code", "eq", "US"),
            new Condition("merchant_category", "ne", "Gambling")
        );

        CompiledCondition compiled = ConditionCompiler.compileAll(conditions);

        // All conditions should match
        assertThat(compiled.matches(transaction)).isTrue();

        // Make one condition fail
        transaction.setMerchantCategory("Gambling");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileAll_EmptyList() {
        CompiledCondition compiled = ConditionCompiler.compileAll(List.of());

        // Empty list = matches all
        assertThat(compiled.matches(transaction)).isTrue();
    }

    @Test
    void testCompileAll_SingleCondition() {
        List<Condition> conditions = List.of(
            new Condition("amount", "gt", 100)
        );

        CompiledCondition compiled = ConditionCompiler.compileAll(conditions);

        assertThat(compiled.matches(transaction)).isTrue();
    }

    // ===== Edge Cases =====

    @Test
    void testCompileWithNullValue() {
        Condition condition = new Condition("amount", "gt", null);
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileWithNullFieldValue() {
        Condition condition = new Condition("email", "eq", "test@example.com");
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        // Email is not set
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileUnknownOperator() {
        Condition condition = new Condition("amount", "unknown_op", 100);
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        // Unknown operator returns false
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileBetweenUsesBoundsOrder() {
        Condition condition = new Condition();
        condition.setField("amount");
        condition.setOperator("between");
        condition.setValues(List.of(200, 100));

        CompiledCondition compiled = ConditionCompiler.compile(condition);

        transaction.setAmount(BigDecimal.valueOf(150));
        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setAmount(BigDecimal.valueOf(250));
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileInListUsesSingleValue() {
        Condition condition = new Condition();
        condition.setField("country_code");
        condition.setOperator("in");
        condition.setValue("US");

        CompiledCondition compiled = ConditionCompiler.compile(condition);

        transaction.setCountryCode("US");
        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setCountryCode("CA");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileExistsOperator() {
        Condition condition = new Condition();
        condition.setField("device_id");
        condition.setOperator("exists");

        CompiledCondition compiled = ConditionCompiler.compile(condition);

        transaction.setDeviceId("device-1");
        assertThat(compiled.matches(transaction)).isTrue();

        transaction.setDeviceId(null);
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileRegexInvalidPatternReturnsFalse() {
        Condition condition = new Condition();
        condition.setField("email");
        condition.setOperator("regex");
        condition.setValue("*[");

        CompiledCondition compiled = ConditionCompiler.compile(condition);

        transaction.setEmail("user@example.com");
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileCustomFieldCondition() {
        Condition condition = new Condition();
        condition.setField("custom_score");
        condition.setOperator("eq");
        condition.setValue(7);

        CompiledCondition compiled = ConditionCompiler.compile(condition);

        transaction.addCustomField("custom_score", 7);
        assertThat(compiled.matches(transaction)).isTrue();

        transaction.addCustomField("custom_score", 5);
        assertThat(compiled.matches(transaction)).isFalse();
    }

    @Test
    void testCompileNullOperatorReturnsFalse() {
        Condition condition = new Condition();
        condition.setField("amount");
        condition.setValue(100);

        CompiledCondition compiled = ConditionCompiler.compile(condition);

        transaction.setAmount(BigDecimal.valueOf(150));
        assertThat(compiled.matches(transaction)).isFalse();
    }

    // ===== Operator Aliases =====

    @Test
    void testOperatorAliases_Equals() {
        Condition eq1 = new Condition("amount", "eq", 100);
        Condition eq2 = new Condition("amount", "equals", 100);
        Condition eq3 = new Condition("amount", "=", 100);

        CompiledCondition compiled1 = ConditionCompiler.compile(eq1);
        CompiledCondition compiled2 = ConditionCompiler.compile(eq2);
        CompiledCondition compiled3 = ConditionCompiler.compile(eq3);

        transaction.setAmount(BigDecimal.valueOf(100));

        assertThat(compiled1.matches(transaction)).isTrue();
        assertThat(compiled2.matches(transaction)).isTrue();
        assertThat(compiled3.matches(transaction)).isTrue();
    }

    @Test
    void testOperatorAliases_GreaterThan() {
        Condition gt1 = new Condition("amount", "gt", 100);
        Condition gt2 = new Condition("amount", ">", 100);

        CompiledCondition compiled1 = ConditionCompiler.compile(gt1);
        CompiledCondition compiled2 = ConditionCompiler.compile(gt2);

        transaction.setAmount(BigDecimal.valueOf(150));

        assertThat(compiled1.matches(transaction)).isTrue();
        assertThat(compiled2.matches(transaction)).isTrue();
    }

    // ===== Performance Characteristics =====

    @Test
    void testCompiledConditionIsReusable() {
        Condition condition = new Condition("amount", "gt", 100);
        CompiledCondition compiled = ConditionCompiler.compile(condition);

        // Reuse the same compiled condition multiple times
        for (int i = 0; i < 100; i++) {
            transaction.setAmount(BigDecimal.valueOf(150));
            assertThat(compiled.matches(transaction)).isTrue();
        }
    }

    @Test
    void testCompiledConditionShortCircuits() {
        // Create a condition that will fail on first check
        CompiledCondition compiled = tx -> {
            // First check: amount
            Object amount = tx.getField(TransactionContext.F_AMOUNT);
            if (!(amount instanceof BigDecimal bd && bd.compareTo(BigDecimal.valueOf(1000)) > 0)) {
                return false; // Short-circuit
            }
            // This should not be evaluated
            throw new RuntimeException("Should not reach here");
        };

        transaction.setAmount(BigDecimal.valueOf(50));

        assertThat(compiled.matches(transaction)).isFalse();
    }
}
