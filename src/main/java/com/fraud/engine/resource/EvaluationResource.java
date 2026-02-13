package com.fraud.engine.resource;

import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.engine.RuleEvaluator;
import com.fraud.engine.kafka.EventPublishException;
import com.fraud.engine.outbox.AsyncOutboxDispatcher;
import com.fraud.engine.ruleset.RulesetLoader;
import com.fraud.engine.ruleset.RulesetRegistry;
import com.fraud.engine.resource.dto.*;
import com.fraud.engine.util.EngineMetrics;
import com.fraud.engine.util.RulesetKeyResolver;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;

import java.util.Set;

@Path("/v1/evaluate")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Evaluation", description = "Card fraud rule evaluation endpoints")
public class EvaluationResource {

    private static final Logger LOG = Logger.getLogger(EvaluationResource.class);

    @Inject
    RuleEvaluator ruleEvaluator;

    @Inject
    RulesetLoader rulesetLoader;

    @Inject
    RulesetRegistry rulesetRegistry;

    @Inject
    AsyncOutboxDispatcher asyncOutboxDispatcher;

    @Inject
    RulesetKeyResolver rulesetKeyResolver;

    @Inject
    EngineMetrics engineMetrics;

    @POST
    @Path("/auth")
    @Operation(
            summary = "AUTH evaluation",
            description = "Evaluates a transaction using AUTH ruleset. First-match semantics, fail-open by default."
    )
    @APIResponses({
            @APIResponse(
                    responseCode = "200",
                    description = "Evaluation successful",
                    content = @Content(schema = @Schema(implementation = Decision.class))
            ),
            @APIResponse(responseCode = "500", description = "Internal server error")
    })
    public Response evaluateAuth(
            @RequestBody(
                    description = "Transaction to evaluate",
                    required = true,
                    content = @Content(schema = @Schema(implementation = TransactionContext.class))
            )
            TransactionContext transaction) {

        if (LOG.isDebugEnabled()) {
            LOG.debugf("AUTH evaluation request: transactionId=%s", transaction.getTransactionId());
        }

        return evaluateTransaction(transaction, RuleEvaluator.EVAL_AUTH);
    }

    private Response evaluateTransaction(TransactionContext transaction, String evaluationType) {
        try {
            String rulesetKey = rulesetKeyResolver.resolve(transaction, evaluationType);

            String country = transaction != null ? transaction.getCountryCode() : null;
            long lookupStart = System.nanoTime();
            Ruleset ruleset = rulesetRegistry.getRulesetWithFallback(country, rulesetKey);
            long lookupEnd = System.nanoTime();
            double lookupTimeMs = (lookupEnd - lookupStart) / 1_000_000.0;

            if (ruleset != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debugf("Using ruleset: %s/v%d", rulesetKey, ruleset.getVersion());
                }

                Decision decision = ruleEvaluator.evaluate(transaction, ruleset);

                com.fraud.engine.domain.TimingBreakdown breakdown = decision.getTimingBreakdown();
                if (breakdown == null) {
                    breakdown = new com.fraud.engine.domain.TimingBreakdown();
                    decision.setTimingBreakdown(breakdown);
                }
                breakdown.setRulesetLookupTimeMs(lookupTimeMs);
                breakdown.setRuleEvaluationTimeMs(decision.getProcessingTimeMs() - lookupTimeMs);

                if (decision.getVelocityResults() != null) {
                    breakdown.setVelocityCheckCount(decision.getVelocityResults().size());
                }

                long persistStart = System.nanoTime();
                persistDecisionOutcome(transaction, decision);
                long persistEnd = System.nanoTime();
                double persistTimeMs = (persistEnd - persistStart) / 1_000_000.0;
                breakdown.setRedisOutboxTimeMs(persistTimeMs);

                return Response.ok(SlimAuthResult.from(decision)).build();
            }

            LOG.errorf("Compiled ruleset not found in registry: %s (was it loaded at startup?)", rulesetKey);

            Decision decision = buildErrorDecision(transaction, rulesetKey);

            com.fraud.engine.domain.TimingBreakdown breakdown = new com.fraud.engine.domain.TimingBreakdown();
            breakdown.setRulesetLookupTimeMs(lookupTimeMs);
            decision.setTimingBreakdown(breakdown);

            persistDecisionOutcome(transaction, decision);
            return Response.ok(SlimAuthResult.from(decision)).build();
        } catch (EventPublishException e) {
            LOG.errorf(e, "Kafka publish failed for AUTH evaluation");
            Decision degraded = buildErrorDecision(transaction, rulesetKeyResolver.resolve(transaction, evaluationType));
            return Response.ok(SlimAuthResult.from(degraded)).build();
        } catch (Exception e) {
            LOG.errorf(e, "Error during evaluation");

            Decision decision = buildErrorDecision(transaction, rulesetKeyResolver.resolve(transaction, evaluationType));

            try {
                persistDecisionOutcome(transaction, decision);
                return Response.ok(SlimAuthResult.from(decision)).build();
            } catch (EventPublishException persistEx) {
                LOG.errorf(persistEx, "Kafka publish failed while handling evaluation error");
                return Response.ok(SlimAuthResult.from(decision)).build();
            } catch (Exception persistEx) {
                LOG.errorf(persistEx, "Failed to persist fail-open decision");
                return Response.ok(SlimAuthResult.from(decision)).build();
            }
        }
    }

    private Decision buildErrorDecision(TransactionContext transaction, String rulesetKey) {
        String transactionId = transaction != null ? transaction.getTransactionId() : null;
        Decision decision = new Decision(transactionId, RuleEvaluator.EVAL_AUTH);
        decision.setDecision(Decision.DECISION_APPROVE);
        decision.setEngineMode(Decision.MODE_FAIL_OPEN);
        decision.setEngineErrorCode("INTERNAL_ERROR");
        decision.setEngineErrorMessage("Internal evaluation error");
        decision.setRulesetKey(rulesetKey);
        engineMetrics.incrementFailOpen();
        return decision;
    }

    private void persistDecisionOutcome(TransactionContext transaction, Decision decision) {
        asyncOutboxDispatcher.enqueueAuth(transaction, decision);
    }

    @GET
    @Path("/health")
    @Operation(summary = "Health check", description = "Check if the evaluation service is healthy")
    @APIResponse(responseCode = "200", description = "Service is healthy")
    public Response health() {
        return Response.ok(new HealthResponse("UP", rulesetLoader.isStorageAccessible())).build();
    }

    @GET
    @Path("/rulesets/registry/status")
    @Operation(summary = "Get registry status", description = "Get information about loaded rulesets")
    @APIResponse(responseCode = "200", description = "Registry status")
    public Response getRegistryStatus() {
        Set<String> countries = rulesetRegistry.getCountries();
        int totalRulesets = rulesetRegistry.size();

        RegistryStatus status = new RegistryStatus();
        status.totalRulesets = totalRulesets;
        status.countries = countries.size();
        status.storageAccessible = rulesetLoader.isStorageAccessible();

        return Response.ok(status).build();
    }

    @GET
    @Path("/rulesets/registry/{country}")
    @Operation(summary = "Get rulesets by country", description = "Get all ruleset keys for a country")
    @APIResponse(responseCode = "200", description = "List of ruleset keys")
    public Response getCountryRulesets(@PathParam("country") String country) {
        Set<String> keys = rulesetRegistry.getRulesetKeys(country);
        return Response.ok(new CountryRulesets(country, keys)).build();
    }

    @POST
    @Path("/rulesets/hotswap")
    @Operation(summary = "Hot swap ruleset", description = "Atomically replace a ruleset with a new version")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Hot swap completed"),
            @APIResponse(responseCode = "400", description = "Invalid request")
    })
    public Response hotSwapRuleset(HotSwapRequest request) {
        if (request.key == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse("INVALID_REQUEST", "rulesetKey is required"))
                    .build();
        }

        if (request.version <= 0) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse("INVALID_REQUEST", "version must be positive"))
                    .build();
        }

        String country = request.country != null ? request.country : "global";
        RulesetRegistry.HotSwapResult result =
                rulesetRegistry.hotSwap(country, request.key, request.version);

        if (result.success()) {
            return Response.ok(new HotSwapResponse(
                    true,
                    result.status(),
                    result.message(),
                    result.oldVersion(),
                    request.version
            )).build();
        } else {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new HotSwapResponse(
                            false,
                            result.status(),
                            result.message(),
                            result.oldVersion(),
                            request.version
                    ))
                    .build();
        }
    }

    @POST
    @Path("/rulesets/load")
    @Operation(summary = "Load ruleset", description = "Load and register a ruleset into the registry")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Ruleset loaded"),
            @APIResponse(responseCode = "400", description = "Invalid request"),
            @APIResponse(responseCode = "404", description = "Ruleset not found")
    })
    public Response loadRuleset(LoadRulesetRequest request) {
        if (request.key == null) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse("INVALID_REQUEST", "rulesetKey is required"))
                    .build();
        }

        if (request.version <= 0) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse("INVALID_REQUEST", "version must be positive"))
                    .build();
        }

        String country = request.country != null ? request.country : "global";
        boolean success = rulesetRegistry.loadAndRegister(country, request.key, request.version);

        if (success) {
            return Response.ok(new LoadRulesetResponse(
                    true,
                    "Ruleset loaded successfully",
                    request.key,
                    request.version,
                    country
            )).build();
        } else {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse("LOAD_FAILED", "Failed to load ruleset"))
                    .build();
        }
    }

    @POST
    @Path("/rulesets/bulk-load")
    @Operation(summary = "Bulk load rulesets", description = "Load multiple rulesets into the registry")
    @APIResponse(responseCode = "200", description = "Bulk load completed")
    public Response bulkLoadRulesets(BulkLoadRequest request) {
        if (request.rulesets == null || request.rulesets.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse("INVALID_REQUEST", "rulesets list is required"))
                    .build();
        }

        int loaded = rulesetRegistry.bulkLoad(request.rulesets);
        return Response.ok(new BulkLoadResponse(loaded, request.rulesets.size())).build();
    }
}
