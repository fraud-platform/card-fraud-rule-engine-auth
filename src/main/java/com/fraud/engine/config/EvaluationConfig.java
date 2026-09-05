package com.fraud.engine.config;

import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.security.SecureRandom;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Configuration for rule evaluation behavior.
 * <p>
 * Controls debug mode and evaluation settings across all environments.
 * Use the same compiled ruleset path everywhere - debug mode only affects
 * the verbosity of output, not the execution path.
 * <p>
 * <b>Zero-Overhead Debug:</b> Debug mode uses a static final boolean check
 * that is evaluated at compile time. When debug is disabled, the JVM completely
 * eliminates the debug code path with zero runtime overhead.
 *
 * @see ADR-0009 for details on compiled ruleset debug mode
 * @see ADR-0013 for zero-overhead debug mode design
 */
@ApplicationScoped
public class EvaluationConfig {

    /**
     * Static flag for zero-overhead debug check.
     * This is evaluated at class loading time and cached as a constant,
     * providing zero runtime overhead when debug is disabled.
     */
    private static final boolean DEBUG_ENABLED =
            Boolean.getBoolean("app.evaluation.debug.enabled") ||
            Boolean.parseBoolean(System.getenv("APP_EVALUATION_DEBUG_ENABLED"));

    /**
     * Whether debug mode is enabled via config property.
     * Kept for backward compatibility - prefer using static DEBUG_ENABLED flag.
     */
    @ConfigProperty(name = "app.evaluation.debug.enabled", defaultValue = "false")
    public boolean debugEnabled;

    /**
     * Gets the static debug enabled flag for zero-overhead checks.
     *
     * @return true if debug mode is statically enabled
     */
    public static boolean isStaticDebugEnabled() {
        return DEBUG_ENABLED;
    }

    /**
     * Whether to include field values in debug output.
     * <p>
     * May be disabled for PII/privacy reasons.
     * Default: true
     */
    @ConfigProperty(name = "app.evaluation.debug.includeFieldValues", defaultValue = "true")
    public boolean includeFieldValues;

    /**
     * Maximum number of condition evaluations to capture.
     * <p>
     * Prevents memory issues with very large rulesets.
     * Default: 100
     */
    @ConfigProperty(name = "app.evaluation.debug.maxConditionEvaluations", defaultValue = "100")
    public int maxConditionEvaluations;

    /**
     * Percentage of requests to sample for debug (0-100).
     * <p>
     * Allows enabling debug mode on a subset of traffic.
     * Default: 100 (all requests when debug.enabled=true)
     */
    @ConfigProperty(name = "app.evaluation.debug.sampleRate", defaultValue = "100")
    public int debugSampleRate;

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Checks if debug mode should be enabled for this request.
     * <p>
     * Uses static flag first for zero-overhead check in production.
     * Falls back to config property for dynamic control.
     *
     * @return true if debug should be captured
     */
    public boolean shouldCaptureDebug() {
        if (!DEBUG_ENABLED && !debugEnabled) {
            return false;
        }
        if (debugSampleRate >= 100) {
            return true;
        }
        if (debugSampleRate <= 0) {
            return false;
        }
        return RANDOM.nextInt(100) < debugSampleRate;
    }

    /**
     * Non-probabilistic "is debug mode enabled at all" check.
     * <p>
     * Unlike {@link #shouldCaptureDebug()}, this does NOT roll the per-request debug sample
     * rate - it only reflects whether debug mode is switched on globally. Use this wherever a
     * decision needs to stay in sync with another call site's independent {@code
     * shouldCaptureDebug()} roll without re-rolling it (e.g. folding "debug is on" into
     * {@code EvaluationResource}'s detailed-timing sample decision).
     *
     * @return true if debug mode is enabled (statically or via config), regardless of sample rate
     */
    public boolean isDebugEnabled() {
        return DEBUG_ENABLED || debugEnabled;
    }

    /**
     * How often to record the detailed per-phase {@code TimingBreakdown} on AUTH decisions.
     * <p>
     * {@code 1} (default) = record on every request, i.e. today's behavior. {@code N > 1} =
     * record on approximately 1 of every N requests. {@code 0} = never record.
     * <p>
     * This is purely a diagnostic sampling knob for the detailed breakdown - it never affects
     * {@code processingTimeMs} or {@code EngineMetadata}, which are always recorded. Replay and
     * simulation evaluations, and requests with debug capture enabled, always force detailed
     * timing regardless of this setting.
     */
    @ConfigProperty(name = "app.evaluation.timing-sample-every-n", defaultValue = "1")
    public int timingSampleEveryN = 1;

    /**
     * Decides whether the current request should record the detailed {@code TimingBreakdown}.
     * <p>
     * Cheap and contention-free: uses {@link ThreadLocalRandom} rather than a shared counter,
     * so there is no cross-thread contention on the hot path. Safe to call once per request.
     *
     * @return true if this request should record detailed timing
     */
    public boolean shouldSampleDetailedTiming() {
        int n = timingSampleEveryN;
        if (n <= 0) {
            return false;
        }
        if (n == 1) {
            return true;
        }
        return ThreadLocalRandom.current().nextInt(n) == 0;
    }
}
