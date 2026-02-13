package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ConditionTest {

    @Test
    void testEqualsOperator() {
        Condition condition = new Condition("amount", "eq", 100);

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 100);

        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", 200);
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testGreaterThanOperator() {
        Condition condition = new Condition("amount", "gt", 100);

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 150);

        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", 100);
        assertThat(condition.evaluate(context)).isFalse();

        context.put("amount", 50);
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testGreaterThanOrEqualOperator() {
        Condition condition = new Condition("amount", "gte", 100);

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 150);
        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", 100);
        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", 50);
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testLessThanOperator() {
        Condition condition = new Condition("amount", "lt", 100);

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 50);

        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", 100);
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testInOperator() {
        Condition condition = new Condition();
        condition.setField("country_code");
        condition.setOperator("in");
        condition.setValues(java.util.List.of("US", "CA", "UK"));

        Map<String, Object> context = new HashMap<>();

        context.put("country_code", "US");
        assertThat(condition.evaluate(context)).isTrue();

        context.put("country_code", "DE");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testNotInOperator() {
        Condition condition = new Condition();
        condition.setField("country_code");
        condition.setOperator("not_in");
        condition.setValues(java.util.List.of("US", "CA", "UK"));

        Map<String, Object> context = new HashMap<>();

        context.put("country_code", "DE");
        assertThat(condition.evaluate(context)).isTrue();

        context.put("country_code", "US");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testContainsOperator() {
        Condition condition = new Condition();
        condition.setField("merchant_name");
        condition.setOperator("contains");
        condition.setValue("Amazon");

        Map<String, Object> context = new HashMap<>();
        context.put("merchant_name", "Amazon.com");
        assertThat(condition.evaluate(context)).isTrue();

        context.put("merchant_name", "Walmart");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testRegexOperator() {
        Condition condition = new Condition();
        condition.setField("email");
        condition.setOperator("regex");
        condition.setValue(".*@example\\.com$");

        Map<String, Object> context = new HashMap<>();
        context.put("email", "user@example.com");
        assertThat(condition.evaluate(context)).isTrue();

        context.put("email", "user@other.com");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testStartsWithOperator() {
        Condition condition = new Condition();
        condition.setField("card_hash");
        condition.setOperator("starts_with");
        condition.setValue("abc");

        Map<String, Object> context = new HashMap<>();
        context.put("card_hash", "abc123xyz");
        assertThat(condition.evaluate(context)).isTrue();

        context.put("card_hash", "xyzabc");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testEndsWithOperator() {
        Condition condition = new Condition();
        condition.setField("card_hash");
        condition.setOperator("ends_with");
        condition.setValue("xyz");

        Map<String, Object> context = new HashMap<>();
        context.put("card_hash", "abc123xyz");
        assertThat(condition.evaluate(context)).isTrue();

        context.put("card_hash", "abc123xy");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testMissingFieldReturnsFalse() {
        Condition condition = new Condition("amount", "eq", 100);

        Map<String, Object> context = new HashMap<>();
        context.put("other_field", 100);

        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testNullContextReturnsFalse() {
        Condition condition = new Condition("amount", "eq", 100);

        assertThat(condition.evaluate(null)).isFalse();
    }

    @Test
    void testCaseInsensitiveOperators() {
        Condition condition1 = new Condition("amount", "EQ", 100);
        Condition condition2 = new Condition("amount", "equals", 100);
        Condition condition3 = new Condition("amount", "=", 100);

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 100);

        assertThat(condition1.evaluate(context)).isTrue();
        assertThat(condition2.evaluate(context)).isTrue();
        assertThat(condition3.evaluate(context)).isTrue();
    }

    @Test
    void testUnknownOperatorThrowsException() {
        // Phase 5: Unknown operators now default to EQ instead of throwing
        // This is safer and prevents failures from typos
        Condition condition = new Condition("amount", "unknown_op", 100);

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 100);

        // Should default to EQ behavior, so 100 == 100 = true
        assertThat(condition.evaluate(context)).isTrue();
    }

    @Test
    void testOperatorEnumIsNormalized() {
        // Phase 5: Verify operator is normalized to enum
        Condition condition = new Condition("amount", "GT", 100);
        assertThat(condition.getOperatorEnum()).isEqualTo(Condition.Operator.GT);
    }

    @Test
    void testOperatorEnumFromSymbol() {
        // Phase 5: Verify symbol operators are normalized
        Condition condition1 = new Condition("amount", ">", 100);
        assertThat(condition1.getOperatorEnum()).isEqualTo(Condition.Operator.GT);

        Condition condition2 = new Condition("amount", ">=", 100);
        assertThat(condition2.getOperatorEnum()).isEqualTo(Condition.Operator.GTE);

        Condition condition3 = new Condition("amount", "<", 100);
        assertThat(condition3.getOperatorEnum()).isEqualTo(Condition.Operator.LT);

        Condition condition4 = new Condition("amount", "<=", 100);
        assertThat(condition4.getOperatorEnum()).isEqualTo(Condition.Operator.LTE);
    }

    @Test
    void testSetOperatorNormalizesToEnum() {
        // Phase 5: Verify setter normalizes to enum
        Condition condition = new Condition();
        condition.setOperator("ne");
        assertThat(condition.getOperatorEnum()).isEqualTo(Condition.Operator.NE);
    }

    @Test
    void testExistsOperatorChecksPresenceAndNotNull() {
        Condition condition = new Condition();
        condition.setField("customer_id");
        condition.setOperator("exists");

        Map<String, Object> context = new HashMap<>();
        assertThat(condition.evaluate(context)).isFalse();

        context.put("customer_id", null);
        assertThat(condition.evaluate(context)).isFalse();

        context.put("customer_id", "cust-1");
        assertThat(condition.evaluate(context)).isTrue();
    }

    @Test
    void testBetweenOperatorHandlesReversedBounds() {
        Condition condition = new Condition();
        condition.setField("amount");
        condition.setOperator("between");
        condition.setValues(List.of(200, 100));

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 150);
        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", 250);
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testInOperatorUsesSingleValue() {
        Condition condition = new Condition();
        condition.setField("country_code");
        condition.setOperator("in");
        condition.setValue("US");

        Map<String, Object> context = new HashMap<>();
        context.put("country_code", "US");
        assertThat(condition.evaluate(context)).isTrue();

        context.put("country_code", "CA");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testContainsOperatorWithList() {
        Condition condition = new Condition();
        condition.setField("tags");
        condition.setOperator("contains");
        condition.setValue("vip");

        Map<String, Object> context = new HashMap<>();
        context.put("tags", List.of("new", "vip", "promo"));
        assertThat(condition.evaluate(context)).isTrue();

        context.put("tags", List.of("new", "promo"));
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testRegexInvalidPatternReturnsFalse() {
        Condition condition = new Condition();
        condition.setField("email");
        condition.setOperator("regex");
        condition.setValue("*[");

        Map<String, Object> context = new HashMap<>();
        context.put("email", "user@example.com");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testNumericStringEquality() {
        Condition condition = new Condition("amount", "eq", "10");

        Map<String, Object> context = new HashMap<>();
        context.put("amount", "10");
        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", "11");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testToHumanReadableFormatsValues() {
        Condition condition = new Condition();
        condition.setField("country_code");
        condition.setOperator("in");
        condition.setValues(List.of("US", "CA"));

        assertThat(condition.toHumanReadable()).isEqualTo("country_code IN ('US', 'CA')");
    }
}
