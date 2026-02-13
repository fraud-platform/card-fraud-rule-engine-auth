package com.fraud.engine.domain;

import java.util.List;

/**
 * Formats Condition objects into human-readable strings.
 * <p>
 * This class is extracted from Condition.java to separate formatting concerns
 * from the core evaluation logic. It provides consistent formatting for:
 * <ul>
 *   <li>Operator symbols (e.g., ">" instead of "GT")</li>
 *   <li>Value formatting (e.g., quoting strings, listing collections)</li>
 *   <li>Human-readable condition descriptions</li>
 * </ul>
 */
public final class ConditionFormatter {

    private ConditionFormatter() {
    }

    /**
     * Formats a condition into a human-readable string.
     * Example outputs: "amount > 5000", "country IN (US, CA, UK)"
     *
     * @param condition the condition to format
     * @return a formatted string representation
     */
    public static String toHumanReadable(Condition condition) {
        if (condition == null) {
            return "null";
        }

        String opSymbol = getOperatorSymbol(condition.getOperatorEnum());
        String formattedValue = formatValue(condition);
        return condition.getField() + " " + opSymbol + " " + formattedValue;
    }

    /**
     * Formats the condition's value for display.
     *
     * @param condition the condition
     * @return the formatted value string
     */
    static String formatValue(Condition condition) {
        if (condition == null) {
            return "null";
        }

        Object val = condition.getValues() != null ? condition.getValues() : condition.getValue();
        if (val == null) {
            return "null";
        }
        if (val instanceof List<?> list) {
            return "(" + list.stream()
                    .map(ConditionFormatter::formatSingleValue)
                    .collect(java.util.stream.Collectors.joining(", ")) + ")";
        }
        return formatSingleValue(val);
    }

    /**
     * Formats a single value for display.
     *
     * @param val the value to format
     * @return the formatted value string
     */
    private static String formatSingleValue(Object val) {
        if (val == null) {
            return "null";
        }
        if (val instanceof String) {
            return "'" + val + "'";
        }
        return String.valueOf(val);
    }

    /**
     * Gets the operator symbol for display.
     *
     * @param operator the operator enum
     * @return the symbol string
     */
    public static String getOperatorSymbol(Condition.Operator operator) {
        if (operator == null) {
            return "=";
        }
        return switch (operator) {
            case GT -> ">";
            case GTE -> ">=";
            case LT -> "<";
            case LTE -> "<=";
            case EQ -> "=";
            case NE -> "!=";
            case IN -> "IN";
            case NOT_IN -> "NOT IN";
            case BETWEEN -> "BETWEEN";
            case CONTAINS -> "CONTAINS";
            case STARTS_WITH -> "STARTS WITH";
            case ENDS_WITH -> "ENDS WITH";
            case REGEX -> "MATCHES";
            case EXISTS -> "EXISTS";
        };
    }
}
