package com.fraud.engine.engine;

import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.domain.VelocityConfig;
import com.fraud.engine.domain.Rule;
import com.fraud.engine.velocity.VelocityService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

@ApplicationScoped
public class VelocityEvaluator {

    private static final Logger LOG = Logger.getLogger(VelocityEvaluator.class);

    @Inject
    VelocityService velocityService;

    public Decision.VelocityResult checkVelocity(
            TransactionContext transaction,
            Rule rule,
            Decision decision) {
        try {
            return velocityService.checkVelocity(transaction, rule.getVelocity());
        } catch (Exception e) {
            LOG.warnf(e, "Velocity check failed for rule %s, skipping", rule.getId());
            markVelocityDegraded(decision, e);
            return safeVelocityResult(rule.getVelocity());
        }
    }

    public Decision.VelocityResult checkVelocityReadOnly(
            TransactionContext transaction,
            Rule rule,
            Decision decision) {
        try {
            String key = velocityService.buildVelocityKey(transaction, rule.getVelocity());
            long currentCount = velocityService.getCurrentCount(key);
            String dimensionValue = extractDimensionValue(transaction, rule.getVelocity().getDimension());

            return new Decision.VelocityResult(
                    rule.getVelocity().getDimension(),
                    dimensionValue,
                    currentCount,
                    rule.getVelocity().getThreshold(),
                    rule.getVelocity().getWindowSeconds()
            );
        } catch (Exception e) {
            LOG.warnf(e, "Velocity read check failed for rule %s", rule.getId());
            markVelocityDegraded(decision, e);
            return safeVelocityResult(rule.getVelocity());
        }
    }

    private String extractDimensionValue(TransactionContext transaction, String dimension) {
        if (dimension == null || transaction == null) {
            return null;
        }
        int fieldId = com.fraud.engine.domain.FieldRegistry.fromName(dimension);
        if (fieldId < 0) {
            return null;
        }
        Object value = transaction.getField(fieldId);
        return value != null ? String.valueOf(value) : null;
    }

    private Decision.VelocityResult safeVelocityResult(VelocityConfig config) {
        return new Decision.VelocityResult(
                config.getDimension(),
                null,
                0,
                config.getThreshold(),
                config.getWindowSeconds()
        );
    }

    private void markVelocityDegraded(Decision decision, Exception e) {
        if (decision == null) {
            return;
        }
        String mode = decision.getEngineMode();
        if (Decision.MODE_FAIL_OPEN.equals(mode) || Decision.MODE_REPLAY.equals(mode)) {
            return;
        }
        decision.setEngineMode(Decision.MODE_DEGRADED);
        if (decision.getEngineErrorCode() == null) {
            decision.setEngineErrorCode("REDIS_UNAVAILABLE");
        }
        if (decision.getEngineErrorMessage() == null) {
            String message = e != null && e.getMessage() != null ? e.getMessage() : "Velocity check failed";
            decision.setEngineErrorMessage("Velocity check failed: " + message);
        }
    }
}
