package com.fraud.engine.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.Map;
import java.util.Objects;

/**
 * Represents a condition that can be evaluated against a transaction.
 *
 * <p>Conditions compare a transaction field against a value using an operator.
 * Example: amount > 100, card_hash = 'abc123', merchant_category IN ('01', '02')
 *
 * <p>Phase 5 Optimization: Operator is normalized to an enum at deserialization time,
 * eliminating string allocations and comparisons during evaluation.
 */
public class Condition {

    @NotBlank(message = "Field is required")
    @JsonProperty("field")
    private String field;

    @JsonProperty("operator")
    private String operatorRaw; // Raw value for JSON deserialization

    private Operator operator; // Normalized enum - used for evaluation

    @NotNull(message = "Value is required")
    @JsonProperty("value")
    private Object value;

    @JsonProperty("values")
    private Object values;

    public Condition() {
    }

    public Condition(String field, String operator, Object value) {
        this.field = field;
        setOperator(operator);
        this.value = value;
    }

    public Condition(String field, Operator operator, Object value) {
        this.field = field;
        this.operator = operator != null ? operator : Operator.EQ;
        this.operatorRaw = this.operator.name().toLowerCase();
        this.value = value;
    }

    public String getField() {
        return field;
    }

    public void setField(String field) {
        this.field = field;
    }

    /**
     * Gets the normalized operator enum.
     * @return the operator enum
     */
    public Operator getOperatorEnum() {
        return operator;
    }

    /**
     * Sets the operator using the normalized enum.
     * @param operator the operator enum
     */
    public void setOperatorEnum(Operator operator) {
        this.operator = operator != null ? operator : Operator.EQ;
        this.operatorRaw = this.operator.name().toLowerCase();
    }

    /**
     * Sets the operator from a string value.
     * Normalizes to enum at deserialization time (Phase 5 optimization).
     * @param operator the operator string (e.g., "gt", ">", "equals")
     */
    @JsonProperty("operator")
    public void setOperator(String operator) {
        this.operatorRaw = operator;
        this.operator = Operator.fromString(operator);
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }

    public Object getValues() {
        return values;
    }

    public void setValues(Object values) {
        this.values = values;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Condition condition = (Condition) o;
        return Objects.equals(field, condition.field) &&
               Objects.equals(operator, condition.operator) &&
               Objects.equals(value, condition.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(field, operator, value);
    }

    @Override
    public String toString() {
        return "Condition{" +
               "field='" + field + '\'' +
               ", operator='" + operator + '\'' +
               ", value=" + value +
               '}';
    }

    /**
     * Returns a human-readable string representation of this condition.
     * Example outputs: "amount > 5000", "country IN (US, CA, UK)"
     *
     * @return a formatted string representation
     */
    public String toHumanReadable() {
        return ConditionFormatter.toHumanReadable(this);
    }

    /**
     * Evaluates this condition against a transaction context.
     *
     * @param context the transaction context containing field values
     * @return true if the condition is satisfied, false otherwise
     */
    public boolean evaluate(Map<String, Object> context) {
        if (context == null) {
            return false;
        }
        if (operator == Operator.EXISTS) {
            return context.containsKey(field) && context.get(field) != null;
        }
        if (!context.containsKey(field)) {
            return false;
        }

        Object contextValue = context.get(field);
        return evaluateValue(contextValue);
    }

    /**
     * Evaluates this condition against an already-fetched field value.
     * <p>
     * This is an optimization for scenarios where the value has already been
     * retrieved from the context, avoiding redundant map lookups.
     *
     * @param actualValue the actual value from the transaction context
     * @return true if the condition is satisfied, false otherwise
     */
    public boolean evaluateValue(Object actualValue) {
        if (operator == Operator.EXISTS) {
            return actualValue != null;
        }
        return evaluateComparison(actualValue);
    }

    @SuppressWarnings("unchecked")
    private boolean evaluateComparison(Object contextValue) {
        // Phase 5: Use enum switch (faster than string comparison)
        if (operator == null) {
            return false;
        }

        return switch (operator) {
            case EQ -> isEqual(contextValue, value);
            case NE -> !isEqual(contextValue, value);
            case GT -> compareNumeric(contextValue, value) > 0;
            case GTE -> compareNumeric(contextValue, value) >= 0;
            case LT -> compareNumeric(contextValue, value) < 0;
            case LTE -> compareNumeric(contextValue, value) <= 0;
            case IN -> isInList(contextValue);
            case NOT_IN -> !isInList(contextValue);
            case BETWEEN -> isBetween(contextValue);
            case CONTAINS -> containsValue(contextValue);
            case STARTS_WITH -> startsWithValue(contextValue);
            case ENDS_WITH -> endsWithValue(contextValue);
            case REGEX -> matchesRegex(contextValue);
            case EXISTS -> contextValue != null;
        };
    }

    private boolean isEqual(Object contextValue, Object targetValue) {
        if (contextValue == null && targetValue == null) {
            return true;
        }
        if (contextValue == null || targetValue == null) {
            return false;
        }
        if (Objects.equals(contextValue, targetValue)) {
            return true;
        }
        if (isNumeric(contextValue) && isNumeric(targetValue)) {
            return compareNumeric(contextValue, targetValue) == 0;
        }
        return false;
    }

    private boolean isNumeric(Object value) {
        if (value instanceof Number) {
            return true;
        }
        if (value instanceof String) {
            try {
                Double.parseDouble((String) value);
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private boolean isInList(Object contextValue) {
        if (values == null && value == null) {
            return false;
        }
        java.util.List<?> list = null;
        if (values instanceof java.util.List<?> valuesList) {
            list = valuesList;
        } else if (value instanceof java.util.List<?> valueList) {
            list = valueList;
        } else if (value != null) {
            list = java.util.List.of(value);
        }
        if (list == null) {
            return false;
        }
        return list.stream()
                .anyMatch(item -> Objects.equals(contextValue, item));
    }

    private boolean isBetween(Object contextValue) {
        if (contextValue == null) {
            return false;
        }
        Object rangeSource = values != null ? values : value;
        if (!(rangeSource instanceof java.util.List<?> list) || list.size() < 2) {
            return false;
        }
        Object lower = list.get(0);
        Object upper = list.get(1);
        if (!isNumeric(contextValue) || !isNumeric(lower) || !isNumeric(upper)) {
            return false;
        }
        double actual = toDouble(contextValue);
        double min = toDouble(lower);
        double max = toDouble(upper);
        return actual >= Math.min(min, max) && actual <= Math.max(min, max);
    }

    @SuppressWarnings("unchecked")
    private boolean containsValue(Object contextValue) {
        if (contextValue == null || value == null) {
            return false;
        }
        if (contextValue instanceof java.util.List<?> list) {
            return list.stream().anyMatch(item -> Objects.equals(item, value));
        }
        if (contextValue instanceof String stringValue) {
            return stringValue.contains(String.valueOf(value));
        }
        return false;
    }

    private boolean startsWithValue(Object contextValue) {
        if (contextValue instanceof String stringValue && value != null) {
            return stringValue.startsWith(String.valueOf(value));
        }
        return false;
    }

    private boolean endsWithValue(Object contextValue) {
        if (contextValue instanceof String stringValue && value != null) {
            return stringValue.endsWith(String.valueOf(value));
        }
        return false;
    }

    private boolean matchesRegex(Object contextValue) {
        if (contextValue instanceof String stringValue && value != null) {
            try {
                return stringValue.matches(String.valueOf(value));
            } catch (Exception e) {
                return false;
            }
        }
        return false;
    }

    private int compareNumeric(Object contextValue, Object targetValue) {
        if (contextValue == null || targetValue == null) {
            return 0;
        }

        double contextNum = toDouble(contextValue);
        double targetNum = toDouble(targetValue);

        return Double.compare(contextNum, targetNum);
    }

    private double toDouble(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        try {
            return Double.parseDouble(String.valueOf(value));
        } catch (NumberFormatException e) {
            return 0.0;
        }
    }

    // ========== Inner Classes ==========

    /**
     * Normalized operator enum for condition evaluation.
     * <p>
     * Phase 5 Optimization: Using enum instead of string eliminates
     * repeated string allocations and comparisons during evaluation.
     * <p>
     * Operators are normalized at deserialization time from various string formats:
     * <ul>
     *   <li>GT: "gt", ">"</li>
     *   <li>GTE: "gte", ">="</li>
     *   <li>LT: "lt", "<"</li>
     *   <li>LTE: "lte", "<="</li>
     *   <li>EQ: "eq", "equals", "="</li>
     *   <li>NE: "ne", "not_equals", "!="</li>
     *   <li>IN: "in"</li>
     *   <li>NOT_IN: "not_in"</li>
     *   <li>CONTAINS: "contains"</li>
     *   <li>STARTS_WITH: "starts_with"</li>
     *   <li>ENDS_WITH: "ends_with"</li>
     *   <li>REGEX: "regex", "matches"</li>
     *   <li>EXISTS: "exists"</li>
     *   <li>BETWEEN: "between"</li>
     * </ul>
     */
    public enum Operator {

        /**
         * Greater than - checks if the field value is greater than the expected value.
         */
        GT,

        /**
         * Greater than or equal - checks if the field value is greater than or equal to the expected value.
         */
        GTE,

        /**
         * Less than - checks if the field value is less than the expected value.
         */
        LT,

        /**
         * Less than or equal - checks if the field value is less than or equal to the expected value.
         */
        LTE,

        /**
         * Equal - checks if the field value equals the expected value.
         */
        EQ,

        /**
         * Not equal - checks if the field value does not equal the expected value.
         */
        NE,

        /**
         * In list - checks if the field value is in the list of expected values.
         */
        IN,

        /**
         * Not in list - checks if the field value is not in the list of expected values.
         */
        NOT_IN,

        /**
         * Between - checks if the field value is within a range (inclusive).
         */
        BETWEEN,

        /**
         * Contains - checks if the field value contains the expected substring.
         */
        CONTAINS,

        /**
         * Starts with - checks if the field value starts with the expected prefix.
         */
        STARTS_WITH,

        /**
         * Ends with - checks if the field value ends with the expected suffix.
         */
        ENDS_WITH,

        /**
         * Regex - checks if the field value matches the regular expression pattern.
         */
        REGEX,

        /**
         * Exists - checks if the field is present and non-null.
         */
        EXISTS;

        /**
         * Parses a string value into an Operator enum.
         * <p>
         * Supports multiple aliases for each operator:
         * <ul>
         *   <li>GT: "gt", ">"</li>
         *   <li>GTE: "gte", ">="</li>
         *   <li>LT: "lt", "<"</li>
         *   <li>LTE: "lte", "<="</li>
         *   <li>EQ: "eq", "equals", "="</li>
         *   <li>NE: "ne", "not_equals", "!="</li>
         *   <li>IN: "in"</li>
         *   <li>NOT_IN: "not_in"</li>
         *   <li>BETWEEN: "between"</li>
         *   <li>CONTAINS: "contains"</li>
         *   <li>STARTS_WITH: "starts_with"</li>
         *   <li>ENDS_WITH: "ends_with"</li>
         *   <li>REGEX: "regex", "matches"</li>
         * </ul>
         *
         * @param value the string value to parse
         * @return the corresponding Operator enum, or EQ if invalid
         */
        @JsonCreator
        public static Operator fromString(String value) {
            if (value == null || value.isBlank()) {
                return EQ; // Default to equals for null/blank
            }

            String normalized = value.trim().toLowerCase();

            return switch (normalized) {
                case "gt", ">" -> GT;
                case "gte", ">=" -> GTE;
                case "lt", "<" -> LT;
                case "lte", "<=" -> LTE;
                case "eq", "equals", "=" -> EQ;
                case "ne", "not_equals", "!=" -> NE;
                case "in" -> IN;
                case "not_in" -> NOT_IN;
                case "between" -> BETWEEN;
                case "contains" -> CONTAINS;
                case "starts_with" -> STARTS_WITH;
                case "ends_with" -> ENDS_WITH;
                case "regex", "matches" -> REGEX;
                case "exists" -> EXISTS;
                default -> {
                    // Unknown operator - default to equals but log warning in production
                    // For now, return EQ as safe default
                    yield EQ;
                }
            };
        }

        /**
         * Returns the JSON string representation of this operator.
         * Used by Jackson during serialization.
         *
         * @return the lowercase string representation
         */
        @JsonValue
        public String toValue() {
            return name().toLowerCase();
        }

        /**
         * Checks if this is a comparison operator (GT, GTE, LT, LTE).
         *
         * @return true if this is a comparison operator
         */
        public boolean isComparison() {
            return this == GT || this == GTE || this == LT || this == LTE || this == BETWEEN;
        }

        /**
         * Checks if this is an equality operator (EQ, NE).
         *
         * @return true if this is an equality operator
         */
        public boolean isEquality() {
            return this == EQ || this == NE;
        }

        /**
         * Checks if this is a collection operator (IN, NOT_IN).
         *
         * @return true if this is a collection operator
         */
        public boolean isCollection() {
            return this == IN || this == NOT_IN;
        }

        /**
         * Checks if this is a string operator (CONTAINS, STARTS_WITH, ENDS_WITH, REGEX).
         *
         * @return true if this is a string operator
         */
        public boolean isString() {
            return this == CONTAINS || this == STARTS_WITH || this == ENDS_WITH || this == REGEX;
        }
    }
}
