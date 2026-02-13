package com.fraud.engine.simulation;

import com.fraud.engine.domain.Condition;
import com.fraud.engine.domain.DebugInfo;
import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.Rule;
import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.domain.VelocityConfig;
import com.fraud.engine.engine.ConditionCompiler;
import com.fraud.engine.engine.RuleEvaluator;
import com.fraud.engine.velocity.VelocityService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service for simulating rule evaluation with inline ruleset YAML.
 * <p>
 * Unlike normal evaluation:
 * <ul>
 *   <li>No caching (ruleset compiled in-memory each time)</li>
 *   <li>No Kafka publishing (results returned directly)</li>
 *   <li>No Redis writes (read-only for velocity)</li>
 *   <li>Enhanced explanation output</li>
 * </ul>
 *
 * @see ADR-0009 for details on compiled ruleset debug mode
 */
@ApplicationScoped
public class SimulationService {

    private static final Logger LOG = Logger.getLogger(SimulationService.class);

    @Inject
    RuleEvaluator ruleEvaluator;

    @Inject
    VelocityService velocityService;

    private final ObjectMapper yamlMapper;

    public SimulationService() {
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
        this.yamlMapper.registerModule(new JavaTimeModule());
    }

    /**
     * Simulates evaluation with an inline ruleset.
     *
     * @param transaction  the transaction to evaluate
     * @param rulesetYaml  the inline ruleset YAML
     * @return simulation result with enhanced explanations
     */
    public SimulationResult simulate(TransactionContext transaction, String rulesetYaml) {
        long startTime = System.currentTimeMillis();

        try {
            // 1. Parse inline YAML
            Ruleset ruleset = parseRuleset(rulesetYaml);

            // 2. Evaluate with explanation enabled
            // Use replay mode to avoid side effects
            Decision decision = ruleEvaluator.evaluate(transaction, ruleset, true);

            // 3. Build enhanced response
            return buildSimulationResult(transaction, decision, ruleset);

        } catch (InvalidRulesetException e) {
            throw e;
        } catch (Exception e) {
            LOG.errorf(e, "Simulation error");
            throw new SimulationException("Simulation failed", e);
        }
    }

    /**
     * Parses ruleset from YAML string.
     */
    private Ruleset parseRuleset(String yaml) {
        try {
            Ruleset ruleset = yamlMapper.readValue(yaml, Ruleset.class);
            if (ruleset == null) {
                throw new InvalidRulesetException("Ruleset is null");
            }
            if (ruleset.getKey() == null || ruleset.getKey().isBlank()) {
                ruleset.setKey("SIMULATION");
            }
            if (ruleset.getRules() == null) {
                ruleset.setRules(new ArrayList<>());
            }
            return ruleset;
        } catch (Exception e) {
            throw new InvalidRulesetException("Failed to parse ruleset YAML: " + e.getMessage(), e);
        }
    }

    /**
     * Builds an enhanced simulation result.
     */
    private SimulationResult buildSimulationResult(TransactionContext transaction,
                                                    Decision decision,
                                                    Ruleset ruleset) {
        SimulationResult result = new SimulationResult();
        result.setTransactionId(transaction.getTransactionId());
        result.setDecision(decision.getDecision());
        result.setRulesetKey(ruleset.getKey());
        result.setEvaluatedAt(Instant.now());
        result.setEvaluationTimeMs(decision.getProcessingTimeMs());

        // Add matched rules with explanations
        if (decision.getMatchedRules() != null && !decision.getMatchedRules().isEmpty()) {
            result.setMatchedRules(decision.getMatchedRules());

            // Build explanations
            List<String> explanations = new ArrayList<>();
            for (Decision.MatchedRule matched : decision.getMatchedRules()) {
                explanations.add(buildRuleExplanation(matched));
            }
            result.setExplanations(explanations);

            // Set primary explanation
            if (!explanations.isEmpty()) {
                result.setExplanation(buildPrimaryExplanation(decision.getMatchedRules()));
            }
        }

        // Add velocity results if present
        if (decision.getVelocityResults() != null && !decision.getVelocityResults().isEmpty()) {
            result.setVelocityResults(decision.getVelocityResults());
        }

        // Add debug info if available
        if (decision.getDebugInfo() != null) {
            result.setDebugInfo(decision.getDebugInfo());
        }

        // Add engine mode info
        if (decision.getEngineMode() != null) {
            result.setEngineMode(decision.getEngineMode());
        }

        return result;
    }

    /**
     * Builds a human-readable explanation for a matched rule.
     */
    private String buildRuleExplanation(Decision.MatchedRule matched) {
        StringBuilder sb = new StringBuilder();
        sb.append("Rule '").append(matched.getRuleName()).append("' matched");

        if (matched.getConditionsMet() != null && !matched.getConditionsMet().isEmpty()) {
            sb.append(": ");
            sb.append(String.join(", ", matched.getConditionsMet()));
        }

        sb.append(" -> Action: ").append(matched.getAction());

        return sb.toString();
    }

    /**
     * Builds the primary explanation for the decision.
     */
    private String buildPrimaryExplanation(List<Decision.MatchedRule> matchedRules) {
        if (matchedRules == null || matchedRules.isEmpty()) {
            return "No rules matched - defaulted to APPROVE";
        }

        Decision.MatchedRule first = matchedRules.get(0);
        return String.format("Rule '%s' matched with action %s (priority %d)",
                first.getRuleName(), first.getAction(), first.getPriority());
    }

    /**
     * Simulation result class.
     */
    public static class SimulationResult {
        private String transactionId;
        private String decision;
        private String rulesetKey;
        private Integer rulesetVersion;
        private List<?> matchedRules;
        private Map<String, ?> velocityResults;
        private List<String> explanations;
        private String explanation;
        private Instant evaluatedAt;
        private long evaluationTimeMs;
        private String engineMode;
        private Object debugInfo;

        public String getTransactionId() {
            return transactionId;
        }

        public void setTransactionId(String transactionId) {
            this.transactionId = transactionId;
        }

        public String getDecision() {
            return decision;
        }

        public void setDecision(String decision) {
            this.decision = decision;
        }

        public String getRulesetKey() {
            return rulesetKey;
        }

        public void setRulesetKey(String rulesetKey) {
            this.rulesetKey = rulesetKey;
        }

        public Integer getRulesetVersion() {
            return rulesetVersion;
        }

        public void setRulesetVersion(Integer rulesetVersion) {
            this.rulesetVersion = rulesetVersion;
        }

        public List<?> getMatchedRules() {
            return matchedRules;
        }

        public void setMatchedRules(List<?> matchedRules) {
            this.matchedRules = matchedRules;
        }

        public Map<String, ?> getVelocityResults() {
            return velocityResults;
        }

        public void setVelocityResults(Map<String, ?> velocityResults) {
            this.velocityResults = velocityResults;
        }

        public List<String> getExplanations() {
            return explanations;
        }

        public void setExplanations(List<String> explanations) {
            this.explanations = explanations;
        }

        public String getExplanation() {
            return explanation;
        }

        public void setExplanation(String explanation) {
            this.explanation = explanation;
        }

        public Instant getEvaluatedAt() {
            return evaluatedAt;
        }

        public void setEvaluatedAt(Instant evaluatedAt) {
            this.evaluatedAt = evaluatedAt;
        }

        public long getEvaluationTimeMs() {
            return evaluationTimeMs;
        }

        public void setEvaluationTimeMs(long evaluationTimeMs) {
            this.evaluationTimeMs = evaluationTimeMs;
        }

        public String getEngineMode() {
            return engineMode;
        }

        public void setEngineMode(String engineMode) {
            this.engineMode = engineMode;
        }

        public Object getDebugInfo() {
            return debugInfo;
        }

        public void setDebugInfo(Object debugInfo) {
            this.debugInfo = debugInfo;
        }
    }

    /**
     * Exception thrown when ruleset validation fails.
     */
    public static class InvalidRulesetException extends RuntimeException {
        public InvalidRulesetException(String message) {
            super(message);
        }

        public InvalidRulesetException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Exception thrown when simulation fails.
     */
    public static class SimulationException extends RuntimeException {
        public SimulationException(String message) {
            super(message);
        }

        public SimulationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
