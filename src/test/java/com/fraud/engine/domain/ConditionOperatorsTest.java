package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ConditionOperatorsTest {

    @Test
    void testLessThanOrEqualOperator() {
        Condition condition = new Condition("amount", "lte", 100);

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 100);
        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", 50);
        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", 150);
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testNotEqualsOperator() {
        Condition condition = new Condition("status", "ne", "BLOCKED");

        Map<String, Object> context = new HashMap<>();
        context.put("status", "ACTIVE");
        assertThat(condition.evaluate(context)).isTrue();

        context.put("status", "BLOCKED");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testNotEqualsWithSymbols() {
        Condition condition = new Condition("status", "!=", "BLOCKED");

        Map<String, Object> context = new HashMap<>();
        context.put("status", "ACTIVE");
        assertThat(condition.evaluate(context)).isTrue();
    }

    @Test
    void testInOperatorWithNumbers() {
        Condition condition = new Condition();
        condition.setField("merchant_category_code");
        condition.setOperator("in");
        condition.setValues(List.of(5411, 5812, 7995));

        Map<String, Object> context = new HashMap<>();
        context.put("merchant_category_code", 5411);
        assertThat(condition.evaluate(context)).isTrue();

        context.put("merchant_category_code", 1234);
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testContainsInList() {
        Condition condition = new Condition();
        condition.setField("tags");
        condition.setOperator("contains");
        condition.setValue("premium");

        Map<String, Object> context = new HashMap<>();
        context.put("tags", List.of("premium", "vip", "gold"));
        assertThat(condition.evaluate(context)).isTrue();

        context.put("tags", List.of("basic", "standard"));
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testNullFieldValueReturnsFalse() {
        Condition condition = new Condition("email", "eq", "test@example.com");

        Map<String, Object> context = new HashMap<>();
        context.put("email", null);

        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testRegexWithInvalidPattern() {
        Condition condition = new Condition();
        condition.setField("email");
        condition.setOperator("regex");
        condition.setValue("[invalid");

        Map<String, Object> context = new HashMap<>();
        context.put("email", "test@example.com");

        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testBigDecimalComparison() {
        Condition condition = new Condition("amount", "gt", new BigDecimal("100.00"));

        Map<String, Object> context = new HashMap<>();
        context.put("amount", new BigDecimal("150.00"));
        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", new BigDecimal("50.00"));
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testStringComparisonWithNumericValue() {
        Condition condition = new Condition("amount", "gt", "100");

        Map<String, Object> context = new HashMap<>();
        context.put("amount", "150");
        assertThat(condition.evaluate(context)).isTrue();

        context.put("amount", "50");
        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testContainsNullValue() {
        Condition condition = new Condition();
        condition.setField("merchant_name");
        condition.setOperator("contains");
        condition.setValue("Amazon");

        Map<String, Object> context = new HashMap<>();
        context.put("merchant_name", null);

        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testStartsWithNullValue() {
        Condition condition = new Condition();
        condition.setField("card_hash");
        condition.setOperator("starts_with");
        condition.setValue("abc");

        Map<String, Object> context = new HashMap<>();
        context.put("card_hash", null);

        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testEndsWithNullValue() {
        Condition condition = new Condition();
        condition.setField("card_hash");
        condition.setOperator("ends_with");
        condition.setValue("xyz");

        Map<String, Object> context = new HashMap<>();
        context.put("card_hash", null);

        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testEqualsWithBigDecimalAndNumber() {
        Condition condition = new Condition("amount", "eq", new BigDecimal("100.00"));

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 100);

        assertThat(condition.evaluate(context)).isTrue();
    }

    @Test
    void testInOperatorWithNullValuesList() {
        Condition condition = new Condition();
        condition.setField("country_code");
        condition.setOperator("in");
        condition.setValues(null);

        Map<String, Object> context = new HashMap<>();
        context.put("country_code", "US");

        assertThat(condition.evaluate(context)).isFalse();
    }

    @Test
    void testInOperatorWithNonListValues() {
        Condition condition = new Condition();
        condition.setField("country_code");
        condition.setOperator("in");
        condition.setValues("US");

        Map<String, Object> context = new HashMap<>();
        context.put("country_code", "US");

        assertThat(condition.evaluate(context)).isFalse();
    }
}
