package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ConditionFormatterTest {

    @Test
    void toHumanReadableReturnsNullLiteralForNullCondition() {
        assertThat(ConditionFormatter.toHumanReadable(null)).isEqualTo("null");
    }

    @Test
    void toHumanReadableFormatsInListWithQuotedStrings() {
        Condition condition = new Condition("country", Condition.Operator.IN, null);
        condition.setValues(List.of("US", "CA"));

        assertThat(ConditionFormatter.toHumanReadable(condition))
                .isEqualTo("country IN ('US', 'CA')");
    }

    @Test
    void formatValueUsesValueWhenValuesIsNull() {
        Condition condition = new Condition("amount", Condition.Operator.GT, 5000);

        assertThat(ConditionFormatter.formatValue(condition)).isEqualTo("5000");
    }

    @Test
    void formatValueReturnsNullLiteralForMissingValue() {
        Condition condition = new Condition("merchant_id", Condition.Operator.EQ, null);
        condition.setValues(null);

        assertThat(ConditionFormatter.formatValue(condition)).isEqualTo("null");
    }

    @Test
    void getOperatorSymbolCoversAllOperators() {
        assertThat(ConditionFormatter.getOperatorSymbol(null)).isEqualTo("=");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.GT)).isEqualTo(">");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.GTE)).isEqualTo(">=");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.LT)).isEqualTo("<");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.LTE)).isEqualTo("<=");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.EQ)).isEqualTo("=");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.NE)).isEqualTo("!=");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.IN)).isEqualTo("IN");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.NOT_IN)).isEqualTo("NOT IN");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.BETWEEN)).isEqualTo("BETWEEN");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.CONTAINS)).isEqualTo("CONTAINS");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.STARTS_WITH)).isEqualTo("STARTS WITH");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.ENDS_WITH)).isEqualTo("ENDS WITH");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.REGEX)).isEqualTo("MATCHES");
        assertThat(ConditionFormatter.getOperatorSymbol(Condition.Operator.EXISTS)).isEqualTo("EXISTS");
    }
}
