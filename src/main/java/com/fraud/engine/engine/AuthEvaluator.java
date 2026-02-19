package com.fraud.engine.engine;

import com.fraud.engine.config.EvaluationConfig;
import com.fraud.engine.domain.Condition;
import com.fraud.engine.domain.DebugInfo;
import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.Rule;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.util.DecisionNormalizer;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class AuthEvaluator {

    private static final Logger LOG = Logger.getLogger(AuthEvaluator.class);

    @Inject
    VelocityEvaluator velocityEvaluator;

    @Inject
    EvaluationConfig evaluationConfig;

    public void evaluate(EvaluationContext context) {
        // Keep AUTH context map lazy; compiled conditions don't require HashMap allocation.
        Map<String, Object> evalContext = context.evalContext();
        List<Rule> rules = context.getRulesToEvaluate();

        if (LOG.isDebugEnabled()) {
            LOG.debugf("AUTH evaluation: %d rules to evaluate", rules.size());
        }

        Map<String, Decision.VelocityResult> replayVelocityCache = context.replayMode() ? new HashMap<>() : null;

        for (Rule rule : rules) {
            if (!rule.isEnabled()) {
                continue;
            }

            if (LOG.isDebugEnabled()) {
                LOG.debugf("Evaluating rule: %s (%s)", rule.getId(), rule.getName());
            }

            if (evalContext == null && (context.isDebugEnabled() || rule.getCompiledCondition() == null)) {
                evalContext = context.transaction().toEvaluationContext();
            }

            boolean ruleMatched = evaluateRule(rule, context.transaction(), evalContext);
            if (context.isDebugEnabled()) {
                trackConditionEvaluations(rule, context.transaction(), evalContext, ruleMatched, context.debugBuilder());
            }

            if (!ruleMatched) {
                continue;
            }

            if (rule.getVelocity() != null) {
                Decision.VelocityResult velocityResult;
                if (context.replayMode()) {
                    velocityResult = velocityEvaluator.checkVelocityReadOnly(
                            context.transaction(), rule, context.decision(), replayVelocityCache);
                } else {
                    velocityResult = velocityEvaluator.checkVelocity(
                            context.transaction(), rule, context.decision());
                }
                context.decision().addVelocityResult(rule.getId(), velocityResult);

                if (velocityResult.isExceeded() && rule.getVelocity().getAction() != null) {
                    applyRuleAction(context, rule, rule.getVelocity().getAction());
                    return;
                }
            }

            if (LOG.isDebugEnabled()) {
                LOG.debugf("Rule matched: %s (%s) - Action: %s",
                        rule.getId(), rule.getName(), rule.getAction());
            }

            Decision.MatchedRule matchedRule = createMatchedRule(rule);
            context.decision().addMatchedRule(matchedRule);
            context.decision().setDecision(
                    DecisionNormalizer.normalizeDecisionType(rule.getAction(), Decision.DECISION_APPROVE));
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("No rules matched, defaulting to APPROVE");
        }
        context.decision().setDecision(Decision.DECISION_APPROVE);
    }

    private boolean evaluateRule(Rule rule, TransactionContext transaction, Map<String, Object> context) {
        if (rule.getCompiledCondition() != null) {
            return rule.getCompiledCondition().matches(transaction);
        }
        if (rule.getConditions() != null) {
            Map<String, Object> resolvedContext = context != null ? context : transaction.toEvaluationContext();
            for (Condition condition : rule.getConditions()) {
                if (!condition.evaluate(resolvedContext)) {
                    return false;
                }
            }
        }
        return true;
    }

    private void applyRuleAction(EvaluationContext context, Rule rule, String actionOverride) {
        Decision.MatchedRule matchedRule = createMatchedRule(rule);
        String action = actionOverride != null ? actionOverride : rule.getAction();
        matchedRule.setAction(DecisionNormalizer.normalizeDecisionType(action, matchedRule.getAction()));
        context.decision().addMatchedRule(matchedRule);
        context.decision().setDecision(
                DecisionNormalizer.normalizeDecisionType(action, Decision.DECISION_APPROVE));
        if (LOG.isDebugEnabled()) {
            LOG.debugf("Applied rule action: %s for rule %s", action, rule.getId());
        }
    }

    private Decision.MatchedRule createMatchedRule(Rule rule) {
        Decision.MatchedRule matched = new Decision.MatchedRule(
                rule.getId(),
                rule.getName(),
                rule.getAction()
        );
        matched.setPriority(rule.getPriority());
        matched.setRuleVersionId(rule.getRuleVersionId());
        matched.setRuleVersion(rule.getRuleVersion());
        matched.setMatched(true);
        matched.setContributing(true);
        return matched;
    }

    private void trackConditionEvaluations(Rule rule, TransactionContext transaction,
                                          Map<String, Object> context,
                                          boolean ruleMatched,
                                          DebugInfo.Builder debugBuilder) {
        List<Condition> conditions = rule.getConditions();
        if (conditions == null || conditions.isEmpty()) {
            return;
        }

        for (Condition condition : conditions) {
            long evalStart = System.nanoTime();
            String fieldName = condition.getField();
            Object actualValue = context.get(fieldName);

            boolean matched = condition.evaluateValue(actualValue);
            long evalTime = System.nanoTime() - evalStart;

            String explanation = buildConditionExplanation(condition, actualValue, matched);

            DebugInfo.ConditionEvaluation eval = new DebugInfo.ConditionEvaluation(
                    rule.getId(),
                    rule.getName(),
                    fieldName,
                    condition.getOperatorEnum() != null ? condition.getOperatorEnum().name() : null,
                    condition.getValue(),
                    actualValue,
                    matched,
                    evalTime,
                    explanation
            );

            debugBuilder.addConditionEvaluation(eval);

            if (evaluationConfig != null && evaluationConfig.includeFieldValues) {
                debugBuilder.addFieldValue(fieldName, actualValue);
            }

            if (evaluationConfig != null && debugBuilder.getConditionEvaluationCount() >= evaluationConfig.maxConditionEvaluations) {
                break;
            }
        }
    }

    private String buildConditionExplanation(Condition condition, Object actualValue, boolean matched) {
        return String.format("%s(%s) %s %s = %s",
                condition.getField(),
                actualValue,
                getOperatorSymbol(condition.getOperatorEnum()),
                condition.getValue(),
                matched ? "true" : "false"
        );
    }

    private String getOperatorSymbol(Condition.Operator operator) {
        if (operator == null) {
            return "=";
        }
        return switch (operator) {
            case EQ -> "==";
            case NE -> "!=";
            case GT -> ">";
            case GTE -> ">=";
            case LT -> "<";
            case LTE -> "<=";
            case IN -> "in";
            case NOT_IN -> "not in";
            case BETWEEN -> "between";
            case CONTAINS -> "contains";
            case STARTS_WITH -> "starts with";
            case ENDS_WITH -> "ends with";
            case REGEX -> "matches";
            case EXISTS -> "exists";
        };
    }
}
