package com.fraud.engine.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.engine.RuleEvaluator;
import com.fraud.engine.kafka.DecisionPublisher;
import com.fraud.engine.kafka.EventPublishException;
import com.fraud.engine.outbox.AsyncOutboxDispatcher;
import com.fraud.engine.resource.dto.ErrorResponse;
import com.fraud.engine.util.DecisionNormalizer;
import com.fraud.engine.util.RulesetKeyResolver;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Load shedding filter that limits concurrent requests to protect the service.
 * <p>
 * When the concurrency limit is reached, new requests are "shed" with a
 * fail-open response (APPROVE with DEGRADED mode). This ensures:
 * <ul>
 *   <li>Service remains responsive under extreme load</li>
 *   <li>Existing requests can complete</li>
 *   <li>Transactions are not blocked (fail-open semantics)</li>
 * </ul>
 * <p>
 * This filter only applies to evaluation endpoints (/v1/evaluate/*).
 */
@Provider
@Priority(Priorities.AUTHENTICATION - 100) // Run very early in the filter chain
public class LoadSheddingFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Logger LOG = Logger.getLogger(LoadSheddingFilter.class);
    private static final String PERMIT_ACQUIRED = "loadShedding.permitAcquired";

    @ConfigProperty(name = "app.load-shedding.enabled", defaultValue = "true")
    boolean enabled;

    @ConfigProperty(name = "app.load-shedding.max-concurrent", defaultValue = "100")
    int maxConcurrent;

    @Inject
    ObjectMapper objectMapper;

    @Inject
    AsyncOutboxDispatcher asyncOutboxDispatcher;

    @Inject
    DecisionPublisher decisionPublisher;

    @Inject
    RulesetKeyResolver rulesetKeyResolver;

    private Semaphore permits;
    private final AtomicLong shedCount = new AtomicLong(0);
    private final AtomicLong processedCount = new AtomicLong(0);

    @PostConstruct
    void init() {
        permits = new Semaphore(maxConcurrent, true); // fair=true for predictable behavior
        LOG.infof("LoadSheddingFilter initialized: enabled=%s, maxConcurrent=%d", enabled, maxConcurrent);
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        // Only apply to evaluation endpoints
        String path = requestContext.getUriInfo().getPath();
        if (!path.startsWith("/v1/evaluate")) {
            return;
        }

        if (!enabled) {
            return;
        }

        // Try to acquire a permit
        if (!permits.tryAcquire()) {
            // No permits available - shed this request
            shedCount.incrementAndGet();
            LOG.warnf("Load shedding triggered: concurrent=%d, shed_total=%d",
                    maxConcurrent - permits.availablePermits(), shedCount.get());

            // Return fail-open response
            String evaluationType = resolveEvaluationType(requestContext.getUriInfo().getPath());
            ParsedRequest parsed = parseRequestBody(requestContext);

            String normalizedDecision = null;
            if (RuleEvaluator.EVAL_MONITORING.equalsIgnoreCase(evaluationType)) {
                normalizedDecision = DecisionNormalizer.normalizeMONITORINGDecision(parsed != null ? parsed.decision : null);
                if (normalizedDecision == null) {
                    requestContext.abortWith(
                            Response.status(Response.Status.BAD_REQUEST)
                                    .type(MediaType.APPLICATION_JSON)
                                    .entity(new ErrorResponse("INVALID_REQUEST", "decision must be APPROVE or DECLINE"))
                                    .build()
                    );
                    return;
                }
            }

            Decision shedDecision = createShedDecision(evaluationType, parsed, normalizedDecision);
            String jsonResponse = objectMapper.writeValueAsString(shedDecision);

            ErrorResponse persistenceError = persistShedDecision(parsed, shedDecision, evaluationType);
            if (persistenceError != null) {
                requestContext.abortWith(
                        Response.status(Response.Status.SERVICE_UNAVAILABLE)
                                .type(MediaType.APPLICATION_JSON)
                                .entity(persistenceError)
                                .build()
                );
                return;
            }

            requestContext.abortWith(
                    Response.ok(jsonResponse)
                            .type(MediaType.APPLICATION_JSON)
                            .header("X-Load-Shed", "true")
                            .build()
            );
            return;
        }

        // Permit acquired - mark it so we can release in response filter
        requestContext.setProperty(PERMIT_ACQUIRED, Boolean.TRUE);
        processedCount.incrementAndGet();
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        // Release permit if we acquired one
        Boolean acquired = (Boolean) requestContext.getProperty(PERMIT_ACQUIRED);
        if (Boolean.TRUE.equals(acquired)) {
            permits.release();
        }
    }

    /**
     * Creates a fail-open decision for shed requests.
     */
    private Decision createShedDecision(String evaluationType, ParsedRequest parsed, String normalizedDecision) {
        String transactionId = parsed != null ? parsed.transactionId : null;
        Map<String, Object> context = parsed != null ? parsed.context : null;

        Decision decision = transactionId != null ? new Decision(transactionId, evaluationType) : new Decision();
        decision.setEvaluationType(evaluationType);
        decision.setTransactionId(transactionId);
        decision.setDecision(normalizedDecision != null ? normalizedDecision : Decision.DECISION_APPROVE);
        decision.setEngineMode(Decision.MODE_DEGRADED);
        decision.setEngineErrorCode("LOAD_SHEDDING");
        decision.setEngineErrorMessage("Request shed due to capacity limits");
        decision.setProcessingTimeMs(0);
        decision.setTransactionContext(context);
        TransactionContext tx = parsed != null ? parsed.transactionContext : null;
        decision.setRulesetKey(resolver().resolve(tx, evaluationType));
        return decision;
    }

    private ParsedRequest parseRequestBody(ContainerRequestContext requestContext) {
        ParsedRequest parsed = new ParsedRequest();
        try {
            byte[] body = requestContext.getEntityStream().readAllBytes();
            requestContext.setEntityStream(new ByteArrayInputStream(body));

            if (body.length > 0) {
                JsonNode node = objectMapper.readTree(body);
                parsed.transactionId = readText(node, "transaction_id", "transactionId");
                parsed.decision = readText(node, "decision");
                parsed.context = objectMapper.convertValue(node, Map.class);
                try {
                    parsed.transactionContext = objectMapper.convertValue(node, TransactionContext.class);
                } catch (IllegalArgumentException ignored) {
                    // best-effort
                }
            }
        } catch (Exception e) {
            LOG.debugf("Failed to parse request body for load shed decision: %s", e.getMessage());
        }
        return parsed;
    }

    private String resolveEvaluationType(String path) {
        if (path == null) {
            return RuleEvaluator.EVAL_AUTH;
        }
        String normalized = path.toLowerCase();
        if (normalized.contains("/monitoring")) {
            return RuleEvaluator.EVAL_MONITORING;
        }
        return RuleEvaluator.EVAL_AUTH;
    }

    private String readText(JsonNode node, String... names) {
        if (node == null) {
            return null;
        }
        for (String name : names) {
            JsonNode value = node.get(name);
            if (value != null && value.isTextual()) {
                return value.asText();
            }
        }
        return null;
    }

    private static class ParsedRequest {
        private String transactionId;
        private String decision;
        private Map<String, Object> context;
        private TransactionContext transactionContext;
    }

    /**
     * Gets the current number of available permits.
     */
    public int getAvailablePermits() {
        return permits != null ? permits.availablePermits() : maxConcurrent;
    }

    private ErrorResponse persistShedDecision(ParsedRequest parsed, Decision shedDecision, String evaluationType) {
        try {
            TransactionContext tx = parsed != null ? parsed.transactionContext : null;
            if (tx == null && parsed != null && parsed.context != null) {
                tx = objectMapper.convertValue(parsed.context, TransactionContext.class);
            }
            if (tx != null) {
                shedDecision.setTransactionContext(tx.toEvaluationContext());
            } else if (parsed != null && parsed.context != null) {
                shedDecision.setTransactionContext(parsed.context);
            }

            if (RuleEvaluator.EVAL_AUTH.equalsIgnoreCase(evaluationType)) {
                if (tx == null || tx.getTransactionId() == null) {
                    LOG.warn("Load shed AUTH decision missing transaction context; skipping async durability");
                    return null;
                }
                asyncOutboxDispatcher.enqueueAuth(tx, shedDecision);
                return null;
            }

            if (shedDecision.getTransactionId() == null || decisionPublisher == null) {
                LOG.warn("Load shed MONITORING decision missing transaction_id or publisher");
                return new ErrorResponse("EVENT_PUBLISH_FAILED", "Failed to persist monitoring decision event");
            }
            decisionPublisher.publishDecisionAwait(shedDecision);
            return null;
        } catch (EventPublishException e) {
            LOG.warnf(e, "Failed to publish load shed decision");
            if (RuleEvaluator.EVAL_AUTH.equalsIgnoreCase(evaluationType)) {
                return null;
            }
            return new ErrorResponse("EVENT_PUBLISH_FAILED", "Failed to persist monitoring decision event");
        } catch (Exception e) {
            LOG.warnf(e, "Failed to persist load shed decision");
            if (RuleEvaluator.EVAL_AUTH.equalsIgnoreCase(evaluationType)) {
                return null;
            }
            return new ErrorResponse("EVENT_PUBLISH_FAILED", "Failed to persist monitoring decision event");
        }
    }

    private RulesetKeyResolver resolver() {
        if (rulesetKeyResolver == null) {
            rulesetKeyResolver = new RulesetKeyResolver();
        }
        return rulesetKeyResolver;
    }

    /**
     * Gets the total number of shed requests since startup.
     */
    public long getShedCount() {
        return shedCount.get();
    }

    /**
     * Gets the total number of processed requests since startup.
     */
    public long getProcessedCount() {
        return processedCount.get();
    }

    /**
     * Gets the current utilization percentage.
     */
    public double getUtilization() {
        if (permits == null) return 0.0;
        return (double) (maxConcurrent - permits.availablePermits()) / maxConcurrent * 100;
    }
}
