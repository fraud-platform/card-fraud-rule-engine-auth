package com.fraud.engine.domain;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for the Condition.Operator enum (Phase 5 optimization).
 * <p>
 * These tests verify:
 * <ul>
 *   <li>Operator enum normalization from various string formats</li>
 *   <li>Enum-based evaluation performance</li>
 *   <li>Operator classification methods (isComparison, isEquality, etc.)</li>
 *   <li>Backward compatibility with string-based conditions</li>
 * </ul>
 */
@DisplayName("Condition.Operator Enum Tests (Phase 5)")
class ConditionOperatorTest {

    // ========== fromString() Tests ==========

    @Test
    @DisplayName("Should parse GT operator from 'gt'")
    void shouldParseGtFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("gt");
        assertThat(op).isEqualTo(Condition.Operator.GT);
    }

    @Test
    @DisplayName("Should parse GT operator from '>'")
    void shouldParseGtFromSymbol() {
        Condition.Operator op = Condition.Operator.fromString(">");
        assertThat(op).isEqualTo(Condition.Operator.GT);
    }

    @Test
    @DisplayName("Should parse GTE operator from 'gte'")
    void shouldParseGteFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("gte");
        assertThat(op).isEqualTo(Condition.Operator.GTE);
    }

    @Test
    @DisplayName("Should parse GTE operator from '>='")
    void shouldParseGteFromSymbol() {
        Condition.Operator op = Condition.Operator.fromString(">=");
        assertThat(op).isEqualTo(Condition.Operator.GTE);
    }

    @Test
    @DisplayName("Should parse LT operator from 'lt'")
    void shouldParseLtFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("lt");
        assertThat(op).isEqualTo(Condition.Operator.LT);
    }

    @Test
    @DisplayName("Should parse LT operator from '<'")
    void shouldParseLtFromSymbol() {
        Condition.Operator op = Condition.Operator.fromString("<");
        assertThat(op).isEqualTo(Condition.Operator.LT);
    }

    @Test
    @DisplayName("Should parse LTE operator from 'lte'")
    void shouldParseLteFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("lte");
        assertThat(op).isEqualTo(Condition.Operator.LTE);
    }

    @Test
    @DisplayName("Should parse LTE operator from '<='")
    void shouldParseLteFromSymbol() {
        Condition.Operator op = Condition.Operator.fromString("<=");
        assertThat(op).isEqualTo(Condition.Operator.LTE);
    }

    @Test
    @DisplayName("Should parse EQ operator from 'eq'")
    void shouldParseEqFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("eq");
        assertThat(op).isEqualTo(Condition.Operator.EQ);
    }

    @Test
    @DisplayName("Should parse EQ operator from 'equals'")
    void shouldParseEqFromEquals() {
        Condition.Operator op = Condition.Operator.fromString("equals");
        assertThat(op).isEqualTo(Condition.Operator.EQ);
    }

    @Test
    @DisplayName("Should parse EQ operator from '='")
    void shouldParseEqFromSymbol() {
        Condition.Operator op = Condition.Operator.fromString("=");
        assertThat(op).isEqualTo(Condition.Operator.EQ);
    }

    @Test
    @DisplayName("Should parse NE operator from 'ne'")
    void shouldParseNeFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("ne");
        assertThat(op).isEqualTo(Condition.Operator.NE);
    }

    @Test
    @DisplayName("Should parse NE operator from 'not_equals'")
    void shouldParseNeFromNotEquals() {
        Condition.Operator op = Condition.Operator.fromString("not_equals");
        assertThat(op).isEqualTo(Condition.Operator.NE);
    }

    @Test
    @DisplayName("Should parse NE operator from '!='")
    void shouldParseNeFromSymbol() {
        Condition.Operator op = Condition.Operator.fromString("!=");
        assertThat(op).isEqualTo(Condition.Operator.NE);
    }

    @Test
    @DisplayName("Should parse IN operator from 'in'")
    void shouldParseInFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("in");
        assertThat(op).isEqualTo(Condition.Operator.IN);
    }

    @Test
    @DisplayName("Should parse NOT_IN operator from 'not_in'")
    void shouldParseNotInFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("not_in");
        assertThat(op).isEqualTo(Condition.Operator.NOT_IN);
    }

    @Test
    @DisplayName("Should parse CONTAINS operator from 'contains'")
    void shouldParseContainsFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("contains");
        assertThat(op).isEqualTo(Condition.Operator.CONTAINS);
    }

    @Test
    @DisplayName("Should parse STARTS_WITH operator from 'starts_with'")
    void shouldParseStartsWithFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("starts_with");
        assertThat(op).isEqualTo(Condition.Operator.STARTS_WITH);
    }

    @Test
    @DisplayName("Should parse ENDS_WITH operator from 'ends_with'")
    void shouldParseEndsWithFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("ends_with");
        assertThat(op).isEqualTo(Condition.Operator.ENDS_WITH);
    }

    @Test
    @DisplayName("Should parse REGEX operator from 'regex'")
    void shouldParseRegexFromLowercase() {
        Condition.Operator op = Condition.Operator.fromString("regex");
        assertThat(op).isEqualTo(Condition.Operator.REGEX);
    }

    @Test
    @DisplayName("Should parse REGEX operator from 'matches'")
    void shouldParseRegexFromMatches() {
        Condition.Operator op = Condition.Operator.fromString("matches");
        assertThat(op).isEqualTo(Condition.Operator.REGEX);
    }

    @Test
    @DisplayName("Should handle null input by defaulting to EQ")
    void shouldHandleNullInput() {
        Condition.Operator op = Condition.Operator.fromString(null);
        assertThat(op).isEqualTo(Condition.Operator.EQ);
    }

    @Test
    @DisplayName("Should handle empty string by defaulting to EQ")
    void shouldHandleEmptyString() {
        Condition.Operator op = Condition.Operator.fromString("");
        assertThat(op).isEqualTo(Condition.Operator.EQ);
    }

    @Test
    @DisplayName("Should handle whitespace by trimming")
    void shouldHandleWhitespace() {
        Condition.Operator op = Condition.Operator.fromString("  gt  ");
        assertThat(op).isEqualTo(Condition.Operator.GT);
    }

    @Test
    @DisplayName("Should handle uppercase input")
    void shouldHandleUppercaseInput() {
        Condition.Operator op = Condition.Operator.fromString("GT");
        assertThat(op).isEqualTo(Condition.Operator.GT);
    }

    @Test
    @DisplayName("Should handle mixed case input")
    void shouldHandleMixedCaseInput() {
        Condition.Operator op = Condition.Operator.fromString("Gt");
        assertThat(op).isEqualTo(Condition.Operator.GT);
    }

    @Test
    @DisplayName("Should default unknown operator to EQ")
    void shouldDefaultUnknownOperatorToEq() {
        Condition.Operator op = Condition.Operator.fromString("unknown_operator_xyz");
        assertThat(op).isEqualTo(Condition.Operator.EQ);
    }

    // ========== toValue() Tests ==========

    @Test
    @DisplayName("Should serialize GT to lowercase 'gt'")
    void shouldSerializeGtToLowercase() {
        assertThat(Condition.Operator.GT.toValue()).isEqualTo("gt");
    }

    @Test
    @DisplayName("Should serialize GTE to lowercase 'gte'")
    void shouldSerializeGteToLowercase() {
        assertThat(Condition.Operator.GTE.toValue()).isEqualTo("gte");
    }

    @Test
    @DisplayName("Should serialize LTE to lowercase 'lte'")
    void shouldSerializeLteToLowercase() {
        assertThat(Condition.Operator.LTE.toValue()).isEqualTo("lte");
    }

    @Test
    @DisplayName("Should serialize CONTAINS to lowercase 'contains'")
    void shouldSerializeContainsToLowercase() {
        assertThat(Condition.Operator.CONTAINS.toValue()).isEqualTo("contains");
    }

    // ========== Classification Tests ==========

    @Test
    @DisplayName("GT should be classified as comparison operator")
    void shouldClassifyGtAsComparison() {
        assertThat(Condition.Operator.GT.isComparison()).isTrue();
        assertThat(Condition.Operator.GT.isEquality()).isFalse();
        assertThat(Condition.Operator.GT.isCollection()).isFalse();
        assertThat(Condition.Operator.GT.isString()).isFalse();
    }

    @Test
    @DisplayName("EQ should be classified as equality operator")
    void shouldClassifyEqAsEquality() {
        assertThat(Condition.Operator.EQ.isEquality()).isTrue();
        assertThat(Condition.Operator.EQ.isComparison()).isFalse();
        assertThat(Condition.Operator.EQ.isCollection()).isFalse();
        assertThat(Condition.Operator.EQ.isString()).isFalse();
    }

    @Test
    @DisplayName("IN should be classified as collection operator")
    void shouldClassifyInAsCollection() {
        assertThat(Condition.Operator.IN.isCollection()).isTrue();
        assertThat(Condition.Operator.IN.isComparison()).isFalse();
        assertThat(Condition.Operator.IN.isEquality()).isFalse();
        assertThat(Condition.Operator.IN.isString()).isFalse();
    }

    @Test
    @DisplayName("CONTAINS should be classified as string operator")
    void shouldClassifyContainsAsString() {
        assertThat(Condition.Operator.CONTAINS.isString()).isTrue();
        assertThat(Condition.Operator.CONTAINS.isComparison()).isFalse();
        assertThat(Condition.Operator.CONTAINS.isEquality()).isFalse();
        assertThat(Condition.Operator.CONTAINS.isCollection()).isFalse();
    }

    @Test
    @DisplayName("All comparison operators should be classified correctly")
    void shouldClassifyAllComparisonOperators() {
        assertThat(Condition.Operator.GT.isComparison()).isTrue();
        assertThat(Condition.Operator.GTE.isComparison()).isTrue();
        assertThat(Condition.Operator.LT.isComparison()).isTrue();
        assertThat(Condition.Operator.LTE.isComparison()).isTrue();
    }

    @Test
    @DisplayName("All equality operators should be classified correctly")
    void shouldClassifyAllEqualityOperators() {
        assertThat(Condition.Operator.EQ.isEquality()).isTrue();
        assertThat(Condition.Operator.NE.isEquality()).isTrue();
    }

    @Test
    @DisplayName("All collection operators should be classified correctly")
    void shouldClassifyAllCollectionOperators() {
        assertThat(Condition.Operator.IN.isCollection()).isTrue();
        assertThat(Condition.Operator.NOT_IN.isCollection()).isTrue();
    }

    @Test
    @DisplayName("All string operators should be classified correctly")
    void shouldClassifyAllStringOperators() {
        assertThat(Condition.Operator.CONTAINS.isString()).isTrue();
        assertThat(Condition.Operator.STARTS_WITH.isString()).isTrue();
        assertThat(Condition.Operator.ENDS_WITH.isString()).isTrue();
        assertThat(Condition.Operator.REGEX.isString()).isTrue();
    }

    // ========== Integration with Condition Tests ==========

    @Test
    @DisplayName("Condition should normalize operator to enum on construction")
    void shouldNormalizeOperatorOnConstruction() {
        Condition condition = new Condition("amount", ">", 100);
        assertThat(condition.getOperatorEnum()).isEqualTo(Condition.Operator.GT);
    }

    @Test
    @DisplayName("Condition should evaluate correctly with enum operator")
    void shouldEvaluateWithEnumOperator() {
        Condition condition = new Condition("amount", Condition.Operator.GT, 100);

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 150);

        assertThat(condition.evaluate(context)).isTrue();
    }

    @Test
    @DisplayName("Condition setter should normalize string to enum")
    void shouldNormalizeOnSetOperator() {
        Condition condition = new Condition();
        condition.setOperator("gte");
        assertThat(condition.getOperatorEnum()).isEqualTo(Condition.Operator.GTE);
    }

    @Test
    @DisplayName("Condition getter should return normalized enum operator")
    void shouldReturnNormalizedEnumFromGetter() {
        Condition condition = new Condition("amount", Condition.Operator.GT, 100);
        assertThat(condition.getOperatorEnum()).isEqualTo(Condition.Operator.GT);
    }

    @Test
    @DisplayName("Condition should evaluate with normalized enum operator")
    void shouldEvaluateWithNormalizedEnum() {
        // Create condition with various string formats
        Condition condition1 = new Condition("amount", "GT", 100); // uppercase
        Condition condition2 = new Condition("amount", ">", 100);  // symbol
        Condition condition3 = new Condition("amount", "gt", 100); // lowercase

        Map<String, Object> context = new HashMap<>();
        context.put("amount", 150);

        // All should evaluate the same way
        assertThat(condition1.getOperatorEnum()).isEqualTo(Condition.Operator.GT);
        assertThat(condition2.getOperatorEnum()).isEqualTo(Condition.Operator.GT);
        assertThat(condition3.getOperatorEnum()).isEqualTo(Condition.Operator.GT);

        assertThat(condition1.evaluate(context)).isTrue();
        assertThat(condition2.evaluate(context)).isTrue();
        assertThat(condition3.evaluate(context)).isTrue();
    }

    @Test
    @DisplayName("Enum operator should work with all comparison types")
    void shouldWorkWithAllComparisonTypes() {
        Map<String, Object> context = new HashMap<>();
        context.put("value", 50);

        // Less than
        Condition lt = new Condition("value", Condition.Operator.LT, 100);
        assertThat(lt.evaluate(context)).isTrue();

        // Less than or equal
        Condition lte = new Condition("value", Condition.Operator.LTE, 50);
        assertThat(lte.evaluate(context)).isTrue();

        // Equal
        Condition eq = new Condition("value", Condition.Operator.EQ, 50);
        assertThat(eq.evaluate(context)).isTrue();

        // Not equal
        Condition ne = new Condition("value", Condition.Operator.NE, 100);
        assertThat(ne.evaluate(context)).isTrue();

        // Greater than or equal
        Condition gte = new Condition("value", Condition.Operator.GTE, 50);
        assertThat(gte.evaluate(context)).isTrue();

        // Greater than
        Condition gt = new Condition("value", Condition.Operator.GT, 25);
        assertThat(gt.evaluate(context)).isTrue();
    }

    @Test
    @DisplayName("Enum operator should work with string operators")
    void shouldWorkWithStringOperators() {
        Map<String, Object> context = new HashMap<>();
        context.put("text", "hello world");

        Condition contains = new Condition("text", Condition.Operator.CONTAINS, "lo wo");
        assertThat(contains.evaluate(context)).isTrue();

        Condition startsWith = new Condition("text", Condition.Operator.STARTS_WITH, "hello");
        assertThat(startsWith.evaluate(context)).isTrue();

        Condition endsWith = new Condition("text", Condition.Operator.ENDS_WITH, "world");
        assertThat(endsWith.evaluate(context)).isTrue();

        Condition regex = new Condition("text", Condition.Operator.REGEX, "hello.*world");
        assertThat(regex.evaluate(context)).isTrue();
    }

    @Test
    @DisplayName("Enum operator should work with collection operators")
    void shouldWorkWithCollectionOperators() {
        Map<String, Object> context = new HashMap<>();
        context.put("country", "US");

        Condition in = new Condition("country", Condition.Operator.IN, null);
        in.setValues(java.util.List.of("US", "CA", "UK"));
        assertThat(in.evaluate(context)).isTrue();

        Condition notIn = new Condition("country", Condition.Operator.NOT_IN, null);
        notIn.setValues(java.util.List.of("DE", "FR", "ES"));
        assertThat(notIn.evaluate(context)).isTrue();
    }

    // ========== Round-trip Tests ==========

    @Test
    @DisplayName("Should round-trip operator through enum")
    void shouldRoundTripOperator() {
        String original = "gte";
        Condition.Operator op = Condition.Operator.fromString(original);
        String serialized = op.toValue();

        assertThat(serialized).isEqualTo("gte");
    }

    @Test
    @DisplayName("Should round-trip all operators")
    void shouldRoundTripAllOperators() {
        for (Condition.Operator op : Condition.Operator.values()) {
            String serialized = op.toValue();
            Condition.Operator deserialized = Condition.Operator.fromString(serialized);
            assertThat(deserialized).isEqualTo(op);
        }
    }
}
