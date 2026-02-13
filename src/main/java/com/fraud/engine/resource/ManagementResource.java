package com.fraud.engine.resource;

import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.engine.RuleEvaluator;
import com.fraud.engine.resource.dto.*;
import com.fraud.engine.ruleset.RulesetLoader;
import com.fraud.engine.util.EngineMetrics;
import com.fraud.engine.service.FieldRegistryService;
import com.fraud.engine.simulation.SimulationService;
import com.fraud.engine.simulation.SimulationService.SimulationResult;
import com.fraud.engine.startup.S3StartupValidator;
import com.fraud.engine.watcher.FieldRegistryWatcher;
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

import java.lang.management.ManagementFactory;
import java.util.Optional;

/**
 * Management and Replay API for the card fraud rule engine.
 *
 * <p>These endpoints are used by the UI and admin tools for:
 * <ul>
 *   <li>Transaction replay (testing against historical data)</li>
 *   <li>Debug and simulation mode</li>
 *   <li>Metrics and monitoring</li>
 * </ul>
 *
 * <p><b>Priority Handling:</b> Replay traffic can be configured with lower priority
 * than production traffic via rate limiting or separate request pools.
 */
@Path("/v1/manage")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Management", description = "Management and replay endpoints")
public class ManagementResource {

    private static final Logger LOG = Logger.getLogger(ManagementResource.class);

    @Inject
    RuleEvaluator ruleEvaluator;

    @Inject
    RulesetLoader rulesetLoader;

    @Inject
    SimulationService simulationService;

    @Inject
    FieldRegistryService fieldRegistryService;

    @Inject
    FieldRegistryWatcher fieldRegistryWatcher;

    @Inject
    S3StartupValidator s3StartupValidator;

    @Inject
    EngineMetrics engineMetrics;

    /**
     * Replays a transaction against the ruleset without side effects.
     * <p>
     * This endpoint is used for:
     * <ul>
     *   <li>Testing rule changes against historical transactions</li>
     *   <li>Debugging why a specific decision was made</li>
     *   <li>Analyzing what would happen with different rule configurations</li>
     * </ul>
     *
     * <p><b>Note:</b> Replay evaluations do NOT publish to Kafka and do NOT
     * update velocity counters in Redis. This prevents replay traffic from
     * affecting production state.
     */
    @POST
    @Path("/replay")
    @Operation(
            summary = "Replay transaction evaluation",
            description = "Evaluates a transaction without side effects (no Kafka publish, no velocity update)"
    )
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Replay successful")
    })
    public Response replayTransaction(
            @RequestBody(
                    description = "Transaction to replay",
                    required = true,
                    content = @Content(schema = @Schema(implementation = TransactionContext.class))
            )
            ReplayRequest request) {

        LOG.infof("Replay request: transactionId=%s, rulesetKey=%s, version=%d",
                request.transactionId, request.rulesetKey, request.version);

        try {
            // Determine ruleset key
            String rulesetKey = request.rulesetKey != null ? request.rulesetKey : "CARD_AUTH";

            // Load specified ruleset version (for replay against specific version)
            Decision decision;
            Integer version;
            Optional<Ruleset> compiledOpt;
            if (request.version != null && request.version > 0) {
                compiledOpt = rulesetLoader.loadCompiledRuleset(rulesetKey, request.version);
            } else {
                compiledOpt = rulesetLoader.loadLatestCompiledRuleset(rulesetKey);
            }

            if (compiledOpt.isEmpty()) {
                LOG.warnf("Compiled ruleset not found for replay: %s", rulesetKey);
                return Response.status(Response.Status.NOT_FOUND)
                        .entity(new ErrorResponse("RULESET_NOT_FOUND", "Ruleset not found: " + rulesetKey))
                        .build();
            }

            Ruleset compiledRuleset = compiledOpt.get();
            version = compiledRuleset.getVersion();
            decision = ruleEvaluator.evaluate(request.transaction, compiledRuleset, true);

            LOG.infof("Replay complete: transactionId=%s, decision=%s",
                    request.transactionId, decision.getDecision());

            return Response.ok(new ReplayResponse(decision, version)).build();

        } catch (Exception e) {
            LOG.errorf(e, "Error during replay");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(new ErrorResponse("REPLAY_ERROR", "Replay evaluation failed"))
                    .build();
        }
    }

    /**
     * Batch replay multiple transactions.
     * Useful for testing rule changes against a dataset.
     */
    @POST
    @Path("/replay/batch")
    @Operation(summary = "Batch replay", description = "Replay multiple transactions")
    @APIResponse(responseCode = "200", description = "Batch replay complete")
    public Response replayBatch(BatchReplayRequest request) {
        LOG.infof("Batch replay request: %d transactions", request.transactions.size());

        BatchReplayResponse response = new BatchReplayResponse();
        response.totalCount = request.transactions.size();

        for (TransactionContext transaction : request.transactions) {
            try {
                String rulesetKey = request.rulesetKey != null ? request.rulesetKey : "CARD_AUTH";

                Decision decision = null;
                Optional<Ruleset> compiledOpt;
                if (request.version != null && request.version > 0) {
                    compiledOpt = rulesetLoader.loadCompiledRuleset(rulesetKey, request.version);
                } else {
                    compiledOpt = rulesetLoader.loadLatestCompiledRuleset(rulesetKey);
                }
                if (compiledOpt.isPresent()) {
                    decision = ruleEvaluator.evaluate(transaction, compiledOpt.get(), true);
                }

                if (decision != null) {
                    response.results.add(new BatchReplayResponse.BatchResult(transaction.getTransactionId(), decision, null));
                } else {
                    response.results.add(new BatchReplayResponse.BatchResult(
                            transaction.getTransactionId(), null, "Ruleset not found"));
                    response.failureCount++;
                }
            } catch (Exception e) {
                response.results.add(new BatchReplayResponse.BatchResult(transaction.getTransactionId(), null, "Batch replay item failed"));
                response.failureCount++;
            }
        }

        LOG.infof("Batch replay complete: %d successful, %d failed",
                response.totalCount - response.failureCount, response.failureCount);

        return Response.ok(response).build();
    }

    /**
     * Simulate a transaction with custom ruleset content.
     * Allows testing rules before deploying them.
     */
    @POST
    @Path("/simulate")
    @Operation(summary = "Simulate with custom ruleset", description = "Test with ad-hoc ruleset content")
    @APIResponse(responseCode = "200", description = "Simulation complete")
    @APIResponse(responseCode = "400", description = "Invalid ruleset YAML")
    public Response simulate(SimulationRequest request) {
        try {
            SimulationService.SimulationResult result = simulationService.simulate(
                    request.getTransaction(),
                    request.getRulesetYaml()
            );

            // Convert to DTO for response
            SimulationResult dtoResult = new SimulationResult();
            dtoResult.setTransactionId(result.getTransactionId());
            dtoResult.setDecision(result.getDecision());
            dtoResult.setRulesetKey(result.getRulesetKey());
            dtoResult.setRulesetVersion(result.getRulesetVersion());
            dtoResult.setMatchedRules(result.getMatchedRules());
            dtoResult.setVelocityResults(result.getVelocityResults());
            dtoResult.setExplanations(result.getExplanations());
            dtoResult.setExplanation(result.getExplanation());
            dtoResult.setEvaluatedAt(result.getEvaluatedAt());
            dtoResult.setEvaluationTimeMs(result.getEvaluationTimeMs());
            dtoResult.setEngineMode(result.getEngineMode());
            dtoResult.setDebugInfo(result.getDebugInfo());

            return Response.ok(dtoResult).build();

        } catch (SimulationService.InvalidRulesetException e) {
            LOG.warnf("Invalid ruleset in simulation request: %s", e.getMessage());
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse("INVALID_RULESET", e.getMessage()))
                    .build();
        } catch (SimulationService.SimulationException e) {
            LOG.errorf("Simulation error: %s", e.getMessage());
            return Response.serverError()
                    .entity(new ErrorResponse("SIMULATION_ERROR", "Simulation failed"))
                    .build();
        } catch (Exception e) {
            LOG.errorf(e, "Unexpected simulation error");
            return Response.serverError()
                    .entity(new ErrorResponse("INTERNAL_ERROR", "Internal error during simulation"))
                    .build();
        }
    }

    /**
     * Gets metrics about the rule engine performance.
     */
    @GET
    @Path("/metrics")
    @Operation(summary = "Get engine metrics", description = "Performance and operational metrics")
    @APIResponse(responseCode = "200", description = "Metrics retrieved")
    public Response getMetrics() {
        MetricsResponse metrics = new MetricsResponse();
        metrics.rulesetCacheSize = rulesetLoader.getCacheSize();
        metrics.storageAccessible = rulesetLoader.isStorageAccessible();
        metrics.jvmUptime = ManagementFactory.getRuntimeMXBean().getUptime();
        metrics.jvmMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();

        // Field registry metrics
        metrics.fieldRegistryVersion = fieldRegistryService.getRegistryVersion();
        metrics.fieldRegistrySource = fieldRegistryService.getSource();
        metrics.fieldCount = fieldRegistryService.getFieldCount();
        metrics.fieldRegistryWatcherRunning = fieldRegistryWatcher.isRunning();

        // S3 startup availability (fail-fast status)
        metrics.fieldRegistryS3Available = s3StartupValidator.isFieldRegistryAvailable();
        metrics.rulesetS3Available = s3StartupValidator.isRulesetAvailable();
        metrics.startupHealthy = s3StartupValidator.isStartupHealthy();

        // Engine counters
        metrics.engineCounters = engineMetrics.snapshot();

        return Response.ok(metrics).build();
    }
}
