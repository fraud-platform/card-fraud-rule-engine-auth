package com.fraud.engine.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Edge case tests for Condition operators.
 * Session 2.6: Operator Edge Case Tests
 * Tests REGEX ReDoS, BETWEEN edge cases, IN edge cases, CONTAINS edge cases, and comparison operators.
 */
@DisplayName("Operator Edge Case Tests - Session 2.6")
class OperatorEdgeCaseTest {

    @Nested
    @DisplayName("REGEX Operator Edge Cases")
    class RegexEdgeCases {

        @Test
        @DisplayName("ReDoS pattern - catastrophic backtracking should be handled")
        void testRegexReDoSBacktracking() {
            // This pattern causes catastrophic backtracking
            Condition condition = new Condition();
            condition.setField("email");
            condition.setOperator("regex");
            condition.setValue("(a+)+$");

            Map<String, Object> context = new HashMap<>();
            // Input that triggers exponential backtracking
            context.put("email", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab");

            long startTime = System.currentTimeMillis();
            boolean result = condition.evaluate(context);
            long endTime = System.currentTimeMillis();

            // Should return false and complete in reasonable time (< 1 second)
            assertThat(result).isFalse();
            assertThat(endTime - startTime).isLessThan(1000);
        }

        @Test
        @DisplayName("Nested quantifiers ReDoS pattern")
        void testRegexNestedQuantifiers() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("regex");
            condition.setValue("(a*)*$");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!");

            long startTime = System.currentTimeMillis();
            boolean result = condition.evaluate(context);
            long endTime = System.currentTimeMillis();

            assertThat(result).isFalse();
            assertThat(endTime - startTime).isLessThan(1000);
        }

        @Test
        @DisplayName("Regex with null pattern returns false")
        void testRegexNullPattern() {
            Condition condition = new Condition();
            condition.setField("email");
            condition.setOperator("regex");
            condition.setValue(null);

            Map<String, Object> context = new HashMap<>();
            context.put("email", "test@example.com");

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("Regex with empty pattern matches empty string")
        void testRegexEmptyPattern() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("regex");
            condition.setValue("");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "");

            // Empty pattern matches empty string
            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("Regex with empty pattern on non-empty string - String.matches requires full match")
        void testRegexEmptyPatternOnNonEmpty() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("regex");
            condition.setValue("");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "hello");

            // String.matches("") requires the ENTIRE string to match the empty pattern.
            // "hello".matches("") returns false because "hello" is not an empty string.
            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("Regex with invalid pattern syntax returns false")
        void testRegexInvalidPattern() {
            Condition condition = new Condition();
            condition.setField("email");
            condition.setOperator("regex");
            condition.setValue("[invalid(");

            Map<String, Object> context = new HashMap<>();
            context.put("email", "test@example.com");

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("Regex with unclosed group returns false")
        void testRegexUnclosedGroup() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("regex");
            condition.setValue("(test");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "test");

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("Regex with special characters in input")
        void testRegexSpecialCharactersInInput() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("regex");
            condition.setValue(".*\\$.*");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "Price: $100");

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("Regex with unicode characters")
        void testRegexUnicodeCharacters() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("regex");
            condition.setValue("\\p{L}+");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "Hello");

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("Regex with very long input")
        void testRegexVeryLongInput() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("regex");
            condition.setValue("^.*test.*$");

            Map<String, Object> context = new HashMap<>();
            StringBuilder longText = new StringBuilder();
            for (int i = 0; i < 10000; i++) {
                longText.append("x");
            }
            longText.append("test");
            context.put("text", longText.toString());

            assertThat(condition.evaluate(context)).isTrue();
        }
    }

    @Nested
    @DisplayName("BETWEEN Operator Edge Cases")
    class BetweenEdgeCases {

        @Test
        @DisplayName("BETWEEN with reversed bounds (max < min)")
        void testBetweenReversedBounds() {
            Condition condition = new Condition();
            condition.setField("amount");
            condition.setOperator("between");
            condition.setValues(List.of(1000, 100)); // max=1000, min=100 (reversed)

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 500);

            // Should handle reversed bounds correctly
            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("BETWEEN with equal bounds")
        void testBetweenEqualBounds() {
            Condition condition = new Condition();
            condition.setField("amount");
            condition.setOperator("between");
            condition.setValues(List.of(100, 100));

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 100);

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("BETWEEN with equal bounds - value not equal")
        void testBetweenEqualBoundsNotEqual() {
            Condition condition = new Condition();
            condition.setField("amount");
            condition.setOperator("between");
            condition.setValues(List.of(100, 100));

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 101);

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("BETWEEN with BigDecimal precision")
        void testBetweenBigDecimalPrecision() {
            Condition condition = new Condition();
            condition.setField("amount");
            condition.setOperator("between");
            condition.setValues(List.of(new BigDecimal("0.01"), new BigDecimal("0.03")));

            Map<String, Object> context = new HashMap<>();
            context.put("amount", new BigDecimal("0.02"));

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("BETWEEN with only one bound")
        void testBetweenOneBound() {
            Condition condition = new Condition();
            condition.setField("amount");
            condition.setOperator("between");
            condition.setValues(List.of(100)); // Only one bound

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 50);

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("BETWEEN with empty list")
        void testBetweenEmptyList() {
            Condition condition = new Condition();
            condition.setField("amount");
            condition.setOperator("between");
            condition.setValues(List.of());

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 50);

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("BETWEEN with null bounds")
        void testBetweenNullBounds() {
            Condition condition = new Condition();
            condition.setField("amount");
            condition.setOperator("between");
            condition.setValues(null);

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 50);

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("BETWEEN with negative numbers")
        void testBetweenNegativeNumbers() {
            Condition condition = new Condition();
            condition.setField("amount");
            condition.setOperator("between");
            condition.setValues(List.of(-100, -50));

            Map<String, Object> context = new HashMap<>();
            context.put("amount", -75);

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("BETWEEN at boundary values")
        void testBetweenAtBoundaries() {
            Condition condition = new Condition();
            condition.setField("amount");
            condition.setOperator("between");
            condition.setValues(List.of(100, 200));

            Map<String, Object> context = new HashMap<>();

            // Test at lower boundary
            context.put("amount", 100);
            assertThat(condition.evaluate(context)).isTrue();

            // Test at upper boundary
            context.put("amount", 200);
            assertThat(condition.evaluate(context)).isTrue();

            // Test just outside lower boundary
            context.put("amount", 99);
            assertThat(condition.evaluate(context)).isFalse();

            // Test just outside upper boundary
            context.put("amount", 201);
            assertThat(condition.evaluate(context)).isFalse();
        }
    }

    @Nested
    @DisplayName("IN Operator Edge Cases")
    class InEdgeCases {

        @Test
        @DisplayName("IN with empty list")
        void testInEmptyList() {
            Condition condition = new Condition();
            condition.setField("country_code");
            condition.setOperator("in");
            condition.setValues(List.of());

            Map<String, Object> context = new HashMap<>();
            context.put("country_code", "US");

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("IN with list containing null")
        void testInListWithNull() {
            Condition condition = new Condition();
            condition.setField("status");
            condition.setOperator("in");
            List<Object> values = new ArrayList<>();
            values.add("ACTIVE");
            values.add(null);
            values.add("PENDING");
            condition.setValues(values);

            Map<String, Object> context = new HashMap<>();
            context.put("status", null);

            // null should match null in the list
            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("IN with large list (10000 items)")
        void testInLargeList() {
            Condition condition = new Condition();
            condition.setField("id");
            condition.setOperator("in");

            List<Integer> largeList = new ArrayList<>();
            for (int i = 0; i < 10000; i++) {
                largeList.add(i);
            }
            condition.setValues(largeList);

            Map<String, Object> context = new HashMap<>();
            context.put("id", 9999);

            long startTime = System.currentTimeMillis();
            boolean result = condition.evaluate(context);
            long endTime = System.currentTimeMillis();

            assertThat(result).isTrue();
            assertThat(endTime - startTime).isLessThan(100); // Should be fast even with 10k items
        }

        @Test
        @DisplayName("IN with null list")
        void testInNullList() {
            Condition condition = new Condition();
            condition.setField("country_code");
            condition.setOperator("in");
            condition.setValues(null);

            Map<String, Object> context = new HashMap<>();
            context.put("country_code", "US");

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("IN with mixed types in list")
        void testInMixedTypes() {
            Condition condition = new Condition();
            condition.setField("value");
            condition.setOperator("in");
            condition.setValues(List.of("100", 100, 100.0, new BigDecimal("100")));

            Map<String, Object> context = new HashMap<>();
            context.put("value", 100);

            // Should match the Integer 100 in the list
            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("NOT_IN with empty list")
        void testNotInEmptyList() {
            Condition condition = new Condition();
            condition.setField("country_code");
            condition.setOperator("not_in");
            condition.setValues(List.of());

            Map<String, Object> context = new HashMap<>();
            context.put("country_code", "US");

            // Everything is NOT IN an empty list
            assertThat(condition.evaluate(context)).isTrue();
        }
    }

    @Nested
    @DisplayName("CONTAINS Operator Edge Cases")
    class ContainsEdgeCases {

        @Test
        @DisplayName("CONTAINS with unicode strings")
        void testContainsUnicode() {
            Condition condition = new Condition();
            condition.setField("merchant_name");
            condition.setOperator("contains");
            condition.setValue("日本");

            Map<String, Object> context = new HashMap<>();
            context.put("merchant_name", "日本の店");

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("CONTAINS with emoji")
        void testContainsEmoji() {
            Condition condition = new Condition();
            condition.setField("description");
            condition.setOperator("contains");
            condition.setValue("😀");

            Map<String, Object> context = new HashMap<>();
            context.put("description", "Hello 😀 World");

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("CONTAINS is case sensitive")
        void testContainsCaseSensitive() {
            Condition condition = new Condition();
            condition.setField("merchant_name");
            condition.setOperator("contains");
            condition.setValue("amazon");

            Map<String, Object> context = new HashMap<>();
            context.put("merchant_name", "AMAZON.COM");

            // Case sensitive - should not match
            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("CONTAINS in list")
        void testContainsInList() {
            Condition condition = new Condition();
            condition.setField("tags");
            condition.setOperator("contains");
            condition.setValue("premium");

            Map<String, Object> context = new HashMap<>();
            context.put("tags", List.of("basic", "premium", "gold"));

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("CONTAINS with null context value")
        void testContainsNullContext() {
            Condition condition = new Condition();
            condition.setField("merchant_name");
            condition.setOperator("contains");
            condition.setValue("test");

            Map<String, Object> context = new HashMap<>();
            context.put("merchant_name", null);

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("CONTAINS with null search value")
        void testContainsNullSearch() {
            Condition condition = new Condition();
            condition.setField("merchant_name");
            condition.setOperator("contains");
            condition.setValue(null);

            Map<String, Object> context = new HashMap<>();
            context.put("merchant_name", "test");

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("CONTAINS with RTL characters")
        void testContainsRTL() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("contains");
            condition.setValue("מילה");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "זוהי מילה בעברית");

            assertThat(condition.evaluate(context)).isTrue();
        }
    }

    @Nested
    @DisplayName("Comparison Operator Edge Cases (GT/LT/GTE/LTE)")
    class ComparisonEdgeCases {

        @Test
        @DisplayName("Integer vs Float comparison")
        void testIntegerVsFloatComparison() {
            Condition gtCondition = new Condition("value", "gt", 5.5);

            Map<String, Object> context = new HashMap<>();
            context.put("value", 5); // Integer 5

            // 5 > 5.5 is false
            assertThat(gtCondition.evaluate(context)).isFalse();

            context.put("value", 6); // Integer 6
            // 6 > 5.5 is true
            assertThat(gtCondition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("BigDecimal comparison with double")
        void testBigDecimalVsDouble() {
            Condition condition = new Condition("amount", "eq", new BigDecimal("100.00"));

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 100.0); // Double

            // Should be equal
            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("Comparison with NaN - Double.compare treats NaN as greater than all values")
        void testComparisonWithNaN() {
            Condition condition = new Condition("value", "gt", 0);

            Map<String, Object> context = new HashMap<>();
            context.put("value", Double.NaN);

            // Double.compare(NaN, x) returns 1 per Java spec (NaN is ordered after all values)
            // This means GT returns true - this is the documented Java behavior.
            // In production, NaN values should be filtered at input validation before reaching conditions.
            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("Comparison with Infinity")
        void testComparisonWithInfinity() {
            Condition condition = new Condition("value", "gt", 1000);

            Map<String, Object> context = new HashMap<>();
            context.put("value", Double.POSITIVE_INFINITY);

            assertThat(condition.evaluate(context)).isTrue();

            context.put("value", Double.NEGATIVE_INFINITY);
            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("GTE with equal values")
        void testGTEEqualValues() {
            Condition condition = new Condition("amount", "gte", 100);

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 100);

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("LTE with equal values")
        void testLTEEqualValues() {
            Condition condition = new Condition("amount", "lte", 100);

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 100);

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("GT with string numbers")
        void testGTWithStringNumbers() {
            Condition condition = new Condition("amount", "gt", "100");

            Map<String, Object> context = new HashMap<>();
            context.put("amount", "150");

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("Comparison with very large numbers")
        void testComparisonVeryLargeNumbers() {
            Condition condition = new Condition("amount", "gt", 1e15);

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 1e16);

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("Comparison with very small numbers")
        void testComparisonVerySmallNumbers() {
            Condition condition = new Condition("amount", "gt", 1e-15);

            Map<String, Object> context = new HashMap<>();
            context.put("amount", 1e-10);

            assertThat(condition.evaluate(context)).isTrue();
        }
    }

    @Nested
    @DisplayName("STARTS_WITH and ENDS_WITH Edge Cases")
    class StartsWithEndsWithEdgeCases {

        @Test
        @DisplayName("STARTS_WITH with unicode")
        void testStartsWithUnicode() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("starts_with");
            condition.setValue("こんにちは");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "こんにちは世界");

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("ENDS_WITH with unicode")
        void testEndsWithUnicode() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("ends_with");
            condition.setValue("世界");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "こんにちは世界");

            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("STARTS_WITH with empty prefix")
        void testStartsWithEmpty() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("starts_with");
            condition.setValue("");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "hello");

            // Empty string is prefix of every string
            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("ENDS_WITH with empty suffix")
        void testEndsWithEmpty() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("ends_with");
            condition.setValue("");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "hello");

            // Empty string is suffix of every string
            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("STARTS_WITH with null")
        void testStartsWithNull() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("starts_with");
            condition.setValue("test");

            Map<String, Object> context = new HashMap<>();
            context.put("text", null);

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("ENDS_WITH with null")
        void testEndsWithNull() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("ends_with");
            condition.setValue("test");

            Map<String, Object> context = new HashMap<>();
            context.put("text", null);

            assertThat(condition.evaluate(context)).isFalse();
        }
    }

    @Nested
    @DisplayName("EXISTS Operator Edge Cases")
    class ExistsEdgeCases {

        @Test
        @DisplayName("EXISTS with null value")
        void testExistsWithNullValue() {
            Condition condition = new Condition();
            condition.setField("optional_field");
            condition.setOperator("exists");

            Map<String, Object> context = new HashMap<>();
            context.put("optional_field", null);

            // Field exists but value is null - should be false
            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("EXISTS with empty string")
        void testExistsWithEmptyString() {
            Condition condition = new Condition();
            condition.setField("text");
            condition.setOperator("exists");

            Map<String, Object> context = new HashMap<>();
            context.put("text", "");

            // Field exists with empty string - should be true
            assertThat(condition.evaluate(context)).isTrue();
        }

        @Test
        @DisplayName("EXISTS with missing field")
        void testExistsMissingField() {
            Condition condition = new Condition();
            condition.setField("missing_field");
            condition.setOperator("exists");

            Map<String, Object> context = new HashMap<>();
            context.put("other_field", "value");

            assertThat(condition.evaluate(context)).isFalse();
        }

        @Test
        @DisplayName("EXISTS with zero value")
        void testExistsWithZero() {
            Condition condition = new Condition();
            condition.setField("count");
            condition.setOperator("exists");

            Map<String, Object> context = new HashMap<>();
            context.put("count", 0);

            // Zero is a valid non-null value
            assertThat(condition.evaluate(context)).isTrue();
        }
    }
}
