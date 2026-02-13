package com.fraud.engine.engine;

import com.fraud.engine.domain.Condition;
import com.fraud.engine.domain.CompiledCondition;
import com.fraud.engine.domain.FieldRegistry;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.service.FieldRegistryService;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Compiles conditions into executable lambdas for high-performance evaluation.
 * <p>
 * This compiler transforms {@link Condition} objects (which use string-based field lookup)
 * into {@link CompiledCondition} lambdas (which use direct field access).
 * <p>
 * Phase 5: Now uses {@link Condition.Operator} enum for faster switching.
 * <p>
 * Phase 6: Now uses {@link FieldRegistryService} for dynamic field loading,
 * with fallback to static {@link FieldRegistry} for backward compatibility.
 * <p>
 * The compiler is a CDI bean that can be injected, but also provides static
 * methods for backward compatibility with existing code and tests.
 * <p>
 * Performance benefits:
 * <ul>
 *   <li>Direct array access via {@link TransactionContext#getField(int)} instead of HashMap</li>
 *   <li>No string allocations for field lookups</li>
 *   <li>Better JIT inlining (lambdas are easier to inline than reflective calls)</li>
 *   <li>Monomorphic call sites enable better optimization</li>
 *   <li>Enum switch instead of string switch for operator dispatch</li>
 * </ul>
 */
@ApplicationScoped
public class ConditionCompiler {

    private static final Logger LOG = Logger.getLogger(ConditionCompiler.class);

    // Singleton instance for static method delegates (set by CDI)
    private static volatile ConditionCompiler instance;

    @Inject
    FieldRegistryService fieldRegistryService;

    /**
     * Initializes the compiler and sets the singleton instance for static delegates.
     */
    @PostConstruct
    void init() {
        instance = this;
        LOG.debug("ConditionCompiler instance initialized for static delegates");
    }

    // ========== Static Methods (for backward compatibility) ==========

    /**
     * Compiles a single condition into a lambda predicate (static delegate).
     *
     * @param condition the condition to compile
     * @return a compiled condition that can be evaluated efficiently
     */
    public static CompiledCondition compile(Condition condition) {
        return getInstance().compileCondition(condition);
    }

    /**
     * Compiles a list of conditions (AND logic - all must match) (static delegate).
     *
     * @param conditions the conditions to compile
     * @return a compiled condition that matches only if all input conditions match
     */
    public static CompiledCondition compileAll(List<Condition> conditions) {
        return getInstance().compileAllConditions(conditions);
    }

    /**
     * Gets the singleton instance.
     * Falls back to a no-op instance if CDI hasn't initialized yet (for tests).
     */
    private static ConditionCompiler getInstance() {
        ConditionCompiler result = instance;
        if (result == null) {
            // Fallback for tests or non-CDI contexts
            LOG.debug("ConditionCompiler instance not available, using fallback");
            return new ConditionCompiler();
        }
        return result;
    }

    // ========== Instance Methods ==========

    /**
     * Compiles a single condition into a lambda predicate (instance method).
     *
     * @param condition the condition to compile
     * @return a compiled condition that can be evaluated efficiently
     */
    public CompiledCondition compileCondition(Condition condition) {
        String fieldName = condition.getField();
        Condition.Operator operator = condition.getOperatorEnum();
        Object expectedValue = condition.getValue();
        Object values = condition.getValues();

        // Get field ID from registry (tries service first, falls back to static)
        int fieldId = getFieldId(fieldName);
        if (!FieldRegistry.isValid(fieldId)) {
            return compileCustomFieldCondition(fieldName, operator, expectedValue, values);
        }

        // Phase 5: Use enum switch (faster than string comparison)
        CompiledCondition result;
        if (operator == null) {
            LOG.warnf("Null operator for field %s, defaulting to false", fieldName);
            result = tx -> false;
        } else {
            result = switch (operator) {
                case GT -> compileGreaterThan(fieldId, expectedValue);
                case GTE -> compileGreaterThanOrEqual(fieldId, expectedValue);
                case LT -> compileLessThan(fieldId, expectedValue);
                case LTE -> compileLessThanOrEqual(fieldId, expectedValue);
                case EQ -> compileEquals(fieldId, expectedValue);
                case NE -> compileNotEquals(fieldId, expectedValue);
                case IN -> compileInList(fieldId, values, expectedValue);
                case NOT_IN -> compileNotInList(fieldId, values, expectedValue);
                case BETWEEN -> compileBetween(fieldId, values, expectedValue);
                case CONTAINS -> compileContains(fieldId, expectedValue);
                case STARTS_WITH -> compileStartsWith(fieldId, expectedValue);
                case ENDS_WITH -> compileEndsWith(fieldId, expectedValue);
                case REGEX -> compileRegex(fieldId, expectedValue);
                case EXISTS -> compileExists(fieldId);
            };
        }
        return result;
    }

    /**
     * Compiles a list of conditions (AND logic - all must match) (instance method).
     *
     * @param conditions the conditions to compile
     * @return a compiled condition that matches only if all input conditions match
     */
    public CompiledCondition compileAllConditions(List<Condition> conditions) {
        if (conditions == null || conditions.isEmpty()) {
            return tx -> true; // Empty condition list = matches all
        }

        if (conditions.size() == 1) {
            return compileCondition(conditions.get(0));
        }

        // Combine all conditions with AND - use array for efficiency
        CompiledCondition[] compiled = conditions.stream()
                .map(this::compileCondition)
                .toArray(CompiledCondition[]::new);

        return tx -> {
            for (CompiledCondition c : compiled) {
                if (!c.matches(tx)) {
                    return false; // Short-circuit on first failure
                }
            }
            return true;
        };
    }

    // ========== Compiler Methods ==========

    private CompiledCondition compileGreaterThan(int fieldId, Object expectedValue) {
        if (!(expectedValue instanceof Number)) {
            return tx -> false;
        }
        double threshold = ((Number) expectedValue).doubleValue();
        return tx -> {
            Object actual = tx.getField(fieldId);
            if (actual instanceof Number n) {
                return n.doubleValue() > threshold;
            }
            return false;
        };
    }

    private CompiledCondition compileGreaterThanOrEqual(int fieldId, Object expectedValue) {
        if (!(expectedValue instanceof Number)) {
            return tx -> false;
        }
        double threshold = ((Number) expectedValue).doubleValue();
        return tx -> {
            Object actual = tx.getField(fieldId);
            if (actual instanceof Number n) {
                return n.doubleValue() >= threshold;
            }
            return false;
        };
    }

    private CompiledCondition compileLessThan(int fieldId, Object expectedValue) {
        if (!(expectedValue instanceof Number)) {
            return tx -> false;
        }
        double threshold = ((Number) expectedValue).doubleValue();
        return tx -> {
            Object actual = tx.getField(fieldId);
            if (actual instanceof Number n) {
                return n.doubleValue() < threshold;
            }
            return false;
        };
    }

    private CompiledCondition compileLessThanOrEqual(int fieldId, Object expectedValue) {
        if (!(expectedValue instanceof Number)) {
            return tx -> false;
        }
        double threshold = ((Number) expectedValue).doubleValue();
        return tx -> {
            Object actual = tx.getField(fieldId);
            if (actual instanceof Number n) {
                return n.doubleValue() <= threshold;
            }
            return false;
        };
    }

    private CompiledCondition compileEquals(int fieldId, Object expectedValue) {
        return tx -> {
            Object actual = tx.getField(fieldId);
            if (actual == null && expectedValue == null) return true;
            if (actual == null || expectedValue == null) return false;

            // Numeric comparison
            if (actual instanceof Number actualNum && expectedValue instanceof Number expectedNum) {
                return compareNumeric(actualNum, expectedNum) == 0;
            }

            // String comparison
            return actual.equals(expectedValue);
        };
    }

    private CompiledCondition compileNotEquals(int fieldId, Object expectedValue) {
        CompiledCondition eq = compileEquals(fieldId, expectedValue);
        return tx -> !eq.matches(tx);
    }

    @SuppressWarnings("unchecked")
    private CompiledCondition compileInList(int fieldId, Object values, Object singleValue) {
        List<Object> targetList = extractList(values, singleValue);
        if (targetList == null || targetList.isEmpty()) {
            return tx -> false;
        }

        return tx -> {
            Object actual = tx.getField(fieldId);
            if (actual == null) return false;
            for (Object item : targetList) {
                if (actual.equals(item)) {
                    return true;
                }
            }
            return false;
        };
    }

    @SuppressWarnings("unchecked")
    private CompiledCondition compileNotInList(int fieldId, Object values, Object singleValue) {
        CompiledCondition inCondition = compileInList(fieldId, values, singleValue);
        return tx -> !inCondition.matches(tx);
    }

    private CompiledCondition compileBetween(int fieldId, Object values, Object singleValue) {
        List<Object> range = extractList(values, singleValue);
        if (range == null || range.size() < 2) {
            return tx -> false;
        }
        Object lower = range.get(0);
        Object upper = range.get(1);
        if (!(lower instanceof Number) || !(upper instanceof Number)) {
            return tx -> false;
        }
        double min = ((Number) lower).doubleValue();
        double max = ((Number) upper).doubleValue();
        double low = Math.min(min, max);
        double high = Math.max(min, max);
        return tx -> {
            Object actual = tx.getField(fieldId);
            if (actual instanceof Number n) {
                double val = n.doubleValue();
                return val >= low && val <= high;
            }
            return false;
        };
    }

    private CompiledCondition compileContains(int fieldId, Object expectedValue) {
        if (expectedValue == null) {
            return tx -> false;
        }
        String search = String.valueOf(expectedValue);
        return tx -> {
            Object actual = tx.getField(fieldId);
            if (actual instanceof String s) {
                return s.contains(search);
            }
            return false;
        };
    }

    private CompiledCondition compileStartsWith(int fieldId, Object expectedValue) {
        if (expectedValue == null) {
            return tx -> false;
        }
        String prefix = String.valueOf(expectedValue);
        return tx -> {
            Object actual = tx.getField(fieldId);
            return actual instanceof String s && s.startsWith(prefix);
        };
    }

    private CompiledCondition compileEndsWith(int fieldId, Object expectedValue) {
        if (expectedValue == null) {
            return tx -> false;
        }
        String suffix = String.valueOf(expectedValue);
        return tx -> {
            Object actual = tx.getField(fieldId);
            return actual instanceof String s && s.endsWith(suffix);
        };
    }

    private CompiledCondition compileRegex(int fieldId, Object expectedValue) {
        if (expectedValue == null) {
            return tx -> false;
        }
        String pattern = String.valueOf(expectedValue);
        try {
            Pattern compiledPattern = Pattern.compile(pattern);
            return tx -> {
                Object actual = tx.getField(fieldId);
                return actual instanceof String s && compiledPattern.matcher(s).matches();
            };
        } catch (Exception e) {
            LOG.warnf("Invalid regex pattern: %s", pattern);
            return tx -> false;
        }
    }

    private CompiledCondition compileExists(int fieldId) {
        return tx -> tx.getField(fieldId) != null;
    }

    private CompiledCondition compileCustomFieldCondition(
            String fieldName,
            Condition.Operator operator,
            Object expectedValue,
            Object values) {
        if (fieldName == null || operator == null) {
            return tx -> false;
        }
        Condition condition = new Condition();
        condition.setField(fieldName);
        condition.setOperatorEnum(operator);
        condition.setValue(expectedValue);
        condition.setValues(values);
        return tx -> {
            Map<String, Object> customFields = tx != null ? tx.getCustomFields() : null;
            return condition.evaluate(customFields);
        };
    }

    // ========== Helper Methods ==========

    @SuppressWarnings("unchecked")
    private List<Object> extractList(Object values, Object singleValue) {
        if (values instanceof List<?> list) {
            return (List<Object>) values;
        }
        if (singleValue instanceof List<?> list) {
            return (List<Object>) singleValue;
        }
        if (singleValue != null) {
            return List.of(singleValue);
        }
        return null;
    }

    private static int compareNumeric(Number a, Number b) {
        return Double.compare(a.doubleValue(), b.doubleValue());
    }

    /**
     * Gets the field ID for a given field name.
     * <p>
     * Phase 6: Uses FieldRegistryService if available (dynamic fields from S3),
     * with fallback to static FieldRegistry for backward compatibility.
     *
     * @param fieldName the field name (e.g., "card_hash", "amount")
     * @return the field ID, or {@link FieldRegistry#UNKNOWN} if not found
     */
    private int getFieldId(String fieldName) {
        // Try FieldRegistryService first (dynamic fields from S3)
        if (fieldRegistryService != null) {
            int id = fieldRegistryService.getFieldId(fieldName);
            if (id != FieldRegistry.UNKNOWN) {
                return id;
            }
        }

        // Fallback to static FieldRegistry (builtin fields)
        return FieldRegistry.fromName(fieldName);
    }
}
