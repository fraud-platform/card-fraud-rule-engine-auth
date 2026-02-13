package com.fraud.engine.util;

import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.engine.RuleEvaluator;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RulesetKeyResolverTest {

    private final RulesetKeyResolver resolver = new RulesetKeyResolver();

    @Test
    void resolvesDefaultWhenTransactionNull() {
        assertEquals("CARD_AUTH", resolver.resolve(null, "AUTH"));
    }

    @Test
    void resolvesPurchaseAuth() {
        TransactionContext tx = new TransactionContext();
        tx.setTransactionType("PURCHASE");
        assertEquals("CARD_AUTH", resolver.resolve(tx, "AUTH"));
    }

    @Test
    void resolvesMonitoringForRefundTransactionType() {
        TransactionContext tx = new TransactionContext();
        tx.setTransactionType("REFUND");
        assertEquals("CARD_MONITORING", resolver.resolve(tx, "MONITORING"));
    }

    @Test
    void resolvesAuthForTransferTransactionType() {
        TransactionContext tx = new TransactionContext();
        tx.setTransactionType("TRANSFER");
        assertEquals("CARD_AUTH", resolver.resolve(tx, "AUTH"));
    }

    @Test
    void resolvesAuthForUnknownTransactionType() {
        TransactionContext tx = new TransactionContext();
        tx.setTransactionType("FOO");
        assertEquals("CARD_AUTH", resolver.resolve(tx, "AUTH"));
    }

    @Test
    void resolvesAuthWhenEvaluationTypeNull() {
        assertEquals("CARD_AUTH", resolver.resolve(null, (String) null));
    }

    @Test
    void resolvesFromEnumEvaluationType() {
        TransactionContext tx = new TransactionContext();
        tx.setTransactionType("AUTHORIZATION");
        assertEquals("CARD_MONITORING", resolver.resolve(tx, RuleEvaluator.EvaluationType.MONITORING));
    }
}
