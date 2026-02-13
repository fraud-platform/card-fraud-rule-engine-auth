package com.fraud.engine.kafka;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fraud.engine.domain.Decision;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.reactive.messaging.Channel;
import io.smallrye.reactive.messaging.MutinyEmitter;
import io.smallrye.mutiny.Uni;
import org.jboss.logging.Logger;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service for publishing decision events to Kafka (Redpanda).
 *
 * <p>Publishes enhanced decision events for:
 * - Audit trail
 * - Downstream processing (transaction-management)
 * - Analytics and reporting
 *
 * <p>Events match the DecisionEventCreate schema from transaction-management.
 */
@ApplicationScoped
public class DecisionPublisher {

    private static final Logger LOG = Logger.getLogger(DecisionPublisher.class);

    @Inject
    @Channel("decision-events")
    MutinyEmitter<String> decisionEmitter;

    @Inject
    ObjectMapper objectMapper;

    @ConfigProperty(name = "mp.messaging.outgoing.decision-events.topic", defaultValue = "fraud.card.decisions.v1")
    String topicName;

    /**
     * Publishes a decision event to Kafka.
     *
     * @param decision the decision to publish
     */
    public void publishDecision(Decision decision) {
        try {
            DecisionEventCreate event = toDecisionEventCreate(decision);
            String payload = objectMapper.writeValueAsString(event);

            if (LOG.isDebugEnabled()) {
                LOG.debugf("Publishing decision event: decisionId=%s, transactionId=%s, decision=%s",
                        decision.getDecisionId(),
                        decision.getTransactionId(),
                        decision.getDecision());
            }

            decisionEmitter.send(payload)
                    .subscribe()
                    .with(v -> {
                                if (LOG.isDebugEnabled()) {
                                    LOG.debugf("Decision event published: %s", decision.getDecisionId());
                                }
                            },
                            err -> LOG.errorf(err, "Failed to publish decision event: %s", decision.getDecisionId()));

        } catch (JsonProcessingException e) {
            LOG.errorf(e, "Failed to serialize decision event: %s", decision.getDecisionId());
        } catch (Exception e) {
            LOG.errorf(e, "Failed to publish decision event: %s", decision.getDecisionId());
        }
    }

    /**
     * Publishes a decision event synchronously (blocking).
     *
     * @param decision the decision to publish
     */
    public void publishDecisionSync(Decision decision) {
        publishDecisionAwait(decision);
    }

    /**
     * Publishes a decision event and waits for acknowledgment.
     */
    public void publishDecisionAwait(Decision decision) {
        try {
            DecisionEventCreate event = toDecisionEventCreate(decision);
            String payload = objectMapper.writeValueAsString(event);

            if (LOG.isDebugEnabled()) {
                LOG.debugf("Publishing decision event (await): %s", decision.getDecisionId());
            }

            Uni<Void> uni = decisionEmitter.send(payload);
            uni.await().atMost(Duration.ofSeconds(5));

            if (LOG.isDebugEnabled()) {
                LOG.debugf("Decision event published (await): %s", decision.getDecisionId());
            }

        } catch (JsonProcessingException e) {
            LOG.errorf(e, "Failed to serialize decision event: %s", decision.getDecisionId());
            throw new EventPublishException("Failed to serialize decision event", e);
        } catch (Exception e) {
            LOG.errorf(e, "Failed to publish decision event: %s", decision.getDecisionId());
            throw new EventPublishException("Failed to publish decision event", e);
        }
    }

    /**
     * Publishes a decision event to Kafka asynchronously (fire-and-forget).
     * Does not block the caller - matches the AUTH outbox pattern for performance.
     * Errors are logged but do not fail the request.
     *
     * @param decision the decision to publish
     */
    public void publishDecisionAsync(Decision decision) {
        try {
            DecisionEventCreate event = toDecisionEventCreate(decision);
            String payload = objectMapper.writeValueAsString(event);

            if (LOG.isDebugEnabled()) {
                LOG.debugf("Publishing decision event (async): %s", decision.getDecisionId());
            }

            // Fire-and-forget: return immediately, don't wait for Kafka ack
            decisionEmitter.send(payload)
                .subscribe()
                .with(
                    v -> {
                        if (LOG.isDebugEnabled()) {
                            LOG.debugf("Decision event published (async): %s", decision.getDecisionId());
                        }
                    },
                    err -> LOG.errorf(err, "Failed to publish decision event (async): %s", decision.getDecisionId())
                );

        } catch (JsonProcessingException e) {
            LOG.errorf(e, "Failed to serialize decision event: %s", decision.getDecisionId());
            // Don't throw - just log and continue (fail-open for performance)
        } catch (Exception e) {
            LOG.errorf(e, "Failed to publish decision event: %s", decision.getDecisionId());
            // Don't throw - just log and continue
        }
    }

    /**
     * Converts a Decision to a DecisionEventCreate for Kafka publishing.
     * Matches the transaction-management DecisionEventCreate schema.
     *
     * @param decision the decision object
     * @return the event for publishing
     */
    private DecisionEventCreate toDecisionEventCreate(Decision decision) {
        DecisionEventCreate event = new DecisionEventCreate();

        // Required fields
        event.setTransactionId(decision.getTransactionId());
        event.setOccurredAt(decision.getTimestamp() != null ? decision.getTimestamp().toString() : Instant.now().toString());
        event.setProducedAt(Instant.now().toString());
        event.setDecision(decision.getDecision());
        event.setDecisionReason(determineDecisionReason(decision));
        event.setEvaluationType(decision.getEvaluationType());
        event.setRulesetKey(decision.getRulesetKey());
        event.setRulesetVersion(decision.getRulesetVersion());
        event.setRulesetId(decision.getRulesetId());

        // Transaction details
        if (decision.getTransactionContext() != null) {
            event.setTransaction(buildTransactionDetails(decision));
        }

        // Matched rules
        if (decision.getMatchedRules() != null && !decision.getMatchedRules().isEmpty()) {
            event.setMatchedRules(buildRuleMatches(decision));
        }

        // Risk level (could be calculated based on rules matched)
        event.setRiskLevel(determineRiskLevel(decision));

        // Transaction context (full payload)
        event.setTransactionContext(decision.getTransactionContext());

        // Velocity results (per rule)
        event.setVelocityResults(decision.getVelocityResults());

        // Velocity snapshot
        event.setVelocitySnapshot(decision.getVelocitySnapshot());

        // Engine metadata
        if (decision.getEngineMetadata() != null) {
            event.setEngineMetadata(buildEngineMetadata(decision));
        }

        return event;
    }

    /**
     * Builds the TransactionDetails object from the transaction context.
     * Extracts only the fields needed by transaction-management.
     */
    private DecisionEventCreate.TransactionDetails buildTransactionDetails(Decision decision) {
        DecisionEventCreate.TransactionDetails details = new DecisionEventCreate.TransactionDetails();

        var ctx = decision.getTransactionContext();
        if (ctx == null) {
            return details;
        }

        // Extract card_id from card_hash (tokenized identifier)
        details.setCardId((String) ctx.get("card_hash"));

        // Extract card_last4 if available (need to add this to TransactionContext)
        // For now, we'll derive it from card_hash if it contains enough characters
        String cardHash = (String) ctx.get("card_hash");
        if (cardHash != null && cardHash.length() >= 4) {
            details.setCardLast4(cardHash.substring(cardHash.length() - 4));
        }

        details.setCardNetwork((String) ctx.get("card_network"));
        details.setAmount(ctx.get("amount"));
        details.setCurrency((String) ctx.get("currency"));
        details.setCountry((String) ctx.get("country_code"));
        details.setMerchantId((String) ctx.get("merchant_id"));
        details.setMcc((String) ctx.get("merchant_category_code"));
        details.setIpAddress((String) ctx.get("ip_address"));

        return details;
    }

    /**
     * Builds the list of RuleMatch objects from the decision's matched rules.
     */
    private List<DecisionEventCreate.RuleMatch> buildRuleMatches(Decision decision) {
        return decision.getMatchedRules().stream()
                .map(this::toRuleMatch)
                .collect(Collectors.toList());
    }

    /**
     * Converts a Decision.MatchedRule to a DecisionEventCreate.RuleMatch.
     */
    private DecisionEventCreate.RuleMatch toRuleMatch(Decision.MatchedRule matched) {
        DecisionEventCreate.RuleMatch ruleMatch = new DecisionEventCreate.RuleMatch();

        ruleMatch.setRuleId(matched.getRuleId());
        ruleMatch.setRuleVersion(matched.getRuleVersion());
        ruleMatch.setRuleVersionId(matched.getRuleVersionId());
        ruleMatch.setRuleName(matched.getRuleName());
        ruleMatch.setPriority(matched.getPriority());
        ruleMatch.setRuleAction(matched.getAction());
        ruleMatch.setConditionsMet(matched.getConditionsMet());
        ruleMatch.setConditionValues(matched.getConditionValues());
        ruleMatch.setMatchedAt(Instant.now().toString());
        ruleMatch.setMatchReasonText(buildMatchReasonText(matched));

        return ruleMatch;
    }

    /**
     * Builds a human-readable match reason text.
     */
    private String buildMatchReasonText(Decision.MatchedRule matched) {
        StringBuilder reason = new StringBuilder();
        reason.append("Rule: ").append(matched.getRuleName() != null ? matched.getRuleName() : matched.getRuleId());

        if (matched.getConditionsMet() != null && !matched.getConditionsMet().isEmpty()) {
            reason.append("; Conditions: ").append(String.join(", ", matched.getConditionsMet()));
        }

        return reason.toString();
    }

    /**
     * Converts the engine metadata from Decision to DecisionEventCreate format.
     */
    private DecisionEventCreate.EngineMetadata buildEngineMetadata(Decision decision) {
        DecisionEventCreate.EngineMetadata metadata = new DecisionEventCreate.EngineMetadata();

        var source = decision.getEngineMetadata();
        if (source == null) {
            // Build from decision fields if EngineMetadata is null
            metadata.setEngineMode(decision.getEngineMode());
            metadata.setErrorCode(decision.getEngineErrorCode());
            metadata.setErrorMessage(decision.getEngineErrorMessage());
            metadata.setProcessingTimeMs((double) decision.getProcessingTimeMs());
        } else {
            metadata.setEngineMode(source.getEngineMode());
            metadata.setErrorCode(source.getErrorCode());
            metadata.setErrorMessage(source.getErrorMessage());
            metadata.setProcessingTimeMs(source.getProcessingTimeMs());
            metadata.setRuleEngineVersion(source.getRuleEngineVersion());
        }

        return metadata;
    }

    /**
     * Determines the decision reason based on the decision state.
     */
    private String determineDecisionReason(Decision decision) {
        // If there are velocity results that exceeded, it's a velocity match
        if (decision.getVelocityResults() != null &&
            decision.getVelocityResults().values().stream().anyMatch(Decision.VelocityResult::isExceeded)) {
            return "VELOCITY_MATCH";
        }

        // If there are matched rules, it's a rule match
        if (decision.getMatchedRules() != null && !decision.getMatchedRules().isEmpty()) {
            return "RULE_MATCH";
        }

        // Final decision-based reasons
        String decisionValue = decision.getDecision();
        if (Decision.DECISION_DECLINE.equals(decisionValue)) {
            return "SYSTEM_DECLINE";
        }
        if (Decision.DECISION_APPROVE.equals(decisionValue)) {
            return "DEFAULT_ALLOW";
        }

        return "UNKNOWN";
    }

    /**
     * Determines the risk level based on the decision.
     */
    private String determineRiskLevel(Decision decision) {
        return switch (decision.getDecision()) {
            case Decision.DECISION_DECLINE -> "HIGH";
            case Decision.DECISION_APPROVE -> "LOW";
            default -> "LOW";
        };
    }
}
