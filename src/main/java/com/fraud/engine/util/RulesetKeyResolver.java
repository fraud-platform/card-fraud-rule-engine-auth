package com.fraud.engine.util;

import com.fraud.engine.engine.RuleEvaluator;
import com.fraud.engine.domain.TransactionContext;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class RulesetKeyResolver {

    public String resolve(TransactionContext transaction, String evaluationType) {
        String normalizedType = evaluationType == null ? RuleEvaluator.EVAL_AUTH : evaluationType.trim().toUpperCase();
        return "CARD_" + normalizedType;
    }

    public String resolve(TransactionContext transaction, RuleEvaluator.EvaluationType evaluationType) {
        return resolve(transaction, evaluationType.getValue());
    }
}
