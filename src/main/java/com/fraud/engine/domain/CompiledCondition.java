package com.fraud.engine.domain;

import java.util.function.Predicate;

/**
 * A compiled condition that can be evaluated against a transaction.
 * <p>
 * This is the high-performance alternative to {@link Condition}.
 * Conditions are compiled into executable lambdas at ruleset load time for optimal performance.
 * <p>
 * Benefits over interpretive evaluation:
 * <ul>
 *   <li>No HashMap lookups - direct field access</li>
 *   <li>No string comparisons - integer comparisons</li>
 *   <li>JIT can inline the lambda completely</li>
 *   <li>Monomorphic call sites enable better optimization</li>
 * </ul>
 *
 * @see com.fraud.engine.engine.ConditionCompiler
 */
@FunctionalInterface
public interface CompiledCondition extends Predicate<TransactionContext> {

    /**
     * Evaluates this condition against the given transaction.
     *
     * @param transaction the transaction context
     * @return true if condition matches, false otherwise
     */
    boolean matches(TransactionContext transaction);

    /**
     * Default method - evaluates as a predicate.
     */
    @Override
    default boolean test(TransactionContext transaction) {
        return matches(transaction);
    }

    /**
     * Combines two conditions with AND logic.
     *
     * @param other the other condition
     * @return a new condition that matches only if both match
     */
    default CompiledCondition and(CompiledCondition other) {
        return tx -> this.matches(tx) && other.matches(tx);
    }

    /**
     * Combines two conditions with OR logic.
     *
     * @param other the other condition
     * @return a new condition that matches if either matches
     */
    default CompiledCondition or(CompiledCondition other) {
        return tx -> this.matches(tx) || other.matches(tx);
    }

    /**
     * Negates this condition.
     *
     * @return a new condition that matches if this does not
     */
    default CompiledCondition not() {
        return tx -> !this.matches(tx);
    }
}
