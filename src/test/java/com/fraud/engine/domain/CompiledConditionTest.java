package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CompiledConditionTest {

    @Test
    void predicateHelpersAndOrNotBehaveAsExpected() {
        TransactionContext tx = new TransactionContext();
        tx.setTransactionId("txn-1");

        CompiledCondition alwaysTrue = t -> true;
        CompiledCondition alwaysFalse = t -> false;

        assertThat(alwaysTrue.test(tx)).isTrue();
        assertThat(alwaysFalse.test(tx)).isFalse();
        assertThat(alwaysTrue.and(alwaysFalse).matches(tx)).isFalse();
        assertThat(alwaysTrue.or(alwaysFalse).matches(tx)).isTrue();
        assertThat(alwaysFalse.not().matches(tx)).isTrue();
    }
}
