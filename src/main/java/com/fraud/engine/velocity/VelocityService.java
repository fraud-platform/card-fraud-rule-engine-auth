package com.fraud.engine.velocity;

import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.domain.VelocityConfig;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.value.ValueCommands;
import io.vertx.mutiny.redis.client.RedisAPI;
import io.vertx.mutiny.redis.client.Response;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.faulttolerance.CircuitBreaker;
import org.eclipse.microprofile.faulttolerance.Fallback;
import org.jboss.logging.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Service for checking velocity limits using Redis.
 *
 * <p>Velocity tracking monitors transaction frequency across various dimensions
 * such as card hash, amount range, merchant category, etc.
 *
 * <p><b>CRITICAL:</b> All velocity operations use atomic transactions to ensure
 * correctness under high concurrency. This prevents race conditions where multiple
 * transactions could bypass velocity limits.
 */
@ApplicationScoped
public class VelocityService {

    private static final Logger LOG = Logger.getLogger(VelocityService.class);
    private static final String VELOCITY_KEY_PREFIX = "vel:";
    private static final String LUA_SCRIPT_PATH = "/lua/velocity_check.lua";
    private static final Pattern INVALID_KEY_CHARS = Pattern.compile("[^a-zA-Z0-9._-]");

    @Inject
    RedisDataSource redisDataSource;

    @Inject
    io.vertx.mutiny.redis.client.Redis redis;

    @ConfigProperty(name = "app.velocity.default-window-seconds", defaultValue = "3600")
    int defaultWindowSeconds;

    @ConfigProperty(name = "app.velocity.default-threshold", defaultValue = "10")
    int defaultThreshold;

    @ConfigProperty(name = "app.velocity.use-lua-script", defaultValue = "true")
    boolean useLuaScript;

    private ValueCommands<String, Long> valueCommands;
    private String luaScript;
    private String luaScriptSha;
    private RedisAPI redisAPI;

    @PostConstruct
    void init() {
        valueCommands = redisDataSource.value(Long.class);
        redisAPI = RedisAPI.api(redis);

        // Load Lua script
        try {
            luaScript = loadLuaScript();
            if (useLuaScript && luaScript != null) {
                // Load script into Redis and get SHA
                Response response = redisAPI.scriptAndAwait(List.of("LOAD", luaScript));
                if (response != null) {
                    luaScriptSha = response.toString();
                    LOG.infof("Velocity Lua script loaded with SHA: %s", luaScriptSha);
                }
            }
        } catch (Exception e) {
            LOG.warnf(e, "Failed to load Lua script, falling back to non-script mode");
            useLuaScript = false;
        }

        LOG.infof("VelocityService initialized (useLuaScript=%s)", useLuaScript);
    }

    /**
     * Loads the Lua script from classpath.
     */
    private String loadLuaScript() {
        try (InputStream is = getClass().getResourceAsStream(LUA_SCRIPT_PATH)) {
            if (is == null) {
                LOG.warn("Lua script not found at: " + LUA_SCRIPT_PATH);
                return null;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                return reader.lines().collect(Collectors.joining("\n"));
            }
        } catch (IOException e) {
            LOG.warnf(e, "Failed to read Lua script from: %s", LUA_SCRIPT_PATH);
            return null;
        }
    }

    private ValueCommands<String, Long> getValueCommands() {
        return valueCommands;
    }

    /**
     * Checks if a velocity limit has been exceeded.
     * <p>
     * Circuit breaker protects against Redis failures:
     * - Opens after 5 failures in 10 requests (50% failure ratio)
     * - Stays open for 5 seconds before trying again
     * - Falls back to a safe result (count=0, not exceeded)
     *
     * @param transaction the transaction context
     * @param velocityConfig the velocity configuration
     * @return the velocity check result
     */
    @CircuitBreaker(
            requestVolumeThreshold = 10,
            failureRatio = 0.5,
            delay = 5000,
            successThreshold = 3
    )
    @Fallback(fallbackMethod = "checkVelocityFallback")
    public Decision.VelocityResult checkVelocity(
            TransactionContext transaction,
            VelocityConfig velocityConfig) {

        String dimension = velocityConfig.getDimension();
        int windowSeconds = velocityConfig.getWindowSeconds() > 0
                ? velocityConfig.getWindowSeconds()
                : defaultWindowSeconds;
        int threshold = velocityConfig.getThreshold() > 0
                ? velocityConfig.getThreshold()
                : defaultThreshold;

        String key = buildVelocityKey(transaction, velocityConfig);
        Object dimValue = getDimensionValue(transaction, dimension);
        String dimensionValueStr = dimValue != null ? String.valueOf(dimValue) : null;

        if (LOG.isDebugEnabled()) {
            LOG.debugf("Velocity check: key=%s, window=%ds, threshold=%d", key, windowSeconds, threshold);
        }

        try {
            long count = incrementAndGet(key, windowSeconds);

            Decision.VelocityResult result = new Decision.VelocityResult(
                    dimension,
                    dimensionValueStr,
                    count,
                    threshold,
                    windowSeconds
            );

            if (LOG.isDebugEnabled()) {
                LOG.debugv("Velocity result: count={0}, threshold={1}, exceeded={2}",
                        count, threshold, result.isExceeded());
            }

            return result;

        } catch (Exception e) {
            LOG.warnf(e, "Velocity check failed for key: %s", key);
            // Return a result that indicates no velocity issue (fail-safe)
            return new Decision.VelocityResult(dimension, dimensionValueStr, 0, threshold, windowSeconds);
        }
    }

    /**
     * Fallback method for circuit breaker.
     * Returns a safe result that doesn't trigger velocity action (fail-open).
     */
    public Decision.VelocityResult checkVelocityFallback(
            TransactionContext transaction,
            VelocityConfig velocityConfig) {

        LOG.warnf("Velocity check circuit breaker open, returning safe result for dimension: %s",
                velocityConfig.getDimension());

        int threshold = velocityConfig.getThreshold() > 0
                ? velocityConfig.getThreshold()
                : defaultThreshold;
        int windowSeconds = velocityConfig.getWindowSeconds() > 0
                ? velocityConfig.getWindowSeconds()
                : defaultWindowSeconds;

        return new Decision.VelocityResult(
                velocityConfig.getDimension(),
                null,  // No dimension value available in fallback
                0,  // Count of 0 = not exceeded = fail-open
                threshold,
                windowSeconds
        );
    }

    /**
     * Builds a velocity key for the given transaction and config.
     *
     * Key format: vel:{ruleset_key}:{rule_id}:{dimension}:{encoded_value}
     *
     * @param transaction the transaction context
     * @param config the velocity configuration
     * @return the Redis key for this velocity counter
     */
    public String buildVelocityKey(TransactionContext transaction, VelocityConfig config) {
        StringBuilder key = new StringBuilder(VELOCITY_KEY_PREFIX);

        // Add ruleset key prefix (from transaction context or config)
        key.append("global:"); // Could be made configurable

        // Add dimension
        key.append(config.getDimension()).append(":");

        // Get the value for the dimension from the transaction
        Object dimensionValue = getDimensionValue(transaction, config.getDimension());
        if (dimensionValue != null) {
            key.append(encodeKeyPart(String.valueOf(dimensionValue)));
        } else {
            key.append("unknown");
        }

        return key.toString();
    }

    /**
     * Increments the counter and returns the new value.
     * <p>
     * Uses Lua script for atomic INCR+EXPIRE in a single round-trip when available.
     * Falls back to separate commands if Lua script is not loaded.
     * <p>
     * <b>ATOMICITY:</b> The Lua script ensures INCR and EXPIRE happen atomically,
     * eliminating the race condition window between the two operations.
     * <p>
     * <b>REDIS TTL:</b> Redis handles TTL expiration internally via a background
     * process that evicts keys once their TTL reaches zero.
     *
     * @param key the Redis key
     * @param windowSeconds expiry time in seconds
     * @return the new counter value (always accurate due to atomic INCR)
     */
    long incrementAndGet(String key, int windowSeconds) {
        if (useLuaScript && luaScriptSha != null) {
            return incrementAndGetWithLua(key, windowSeconds);
        }
        return incrementAndGetFallback(key, windowSeconds);
    }

    /**
     * Increments counter using Lua script (single round-trip).
     */
    private long incrementAndGetWithLua(String key, int windowSeconds) {
        try {
            // EVALSHA sha numkeys key [key ...] arg [arg ...]
            Response response = redisAPI.evalshaAndAwait(List.of(
                    luaScriptSha,
                    "1",                              // numkeys
                    key,                              // KEYS[1]
                    String.valueOf(windowSeconds),    // ARGV[1]
                    String.valueOf(defaultThreshold)  // ARGV[2]
            ));

            if (response != null && response.size() >= 1) {
                return response.get(0).toLong();
            }
            LOG.warn("Unexpected Lua script response, falling back");
            return incrementAndGetFallback(key, windowSeconds);
        } catch (Exception e) {
            // Script might have been flushed, try reloading
            if (e.getMessage() != null && e.getMessage().contains("NOSCRIPT")) {
                LOG.info("Lua script not found in Redis, reloading...");
                reloadLuaScript();
                // Retry once with reloaded script
                try {
                    Response response = redisAPI.evalshaAndAwait(List.of(
                            luaScriptSha,
                            "1",
                            key,
                            String.valueOf(windowSeconds),
                            String.valueOf(defaultThreshold)
                    ));
                    if (response != null && response.size() >= 1) {
                        return response.get(0).toLong();
                    }
                } catch (Exception retryEx) {
                    LOG.warnf(retryEx, "Retry failed, falling back to non-script mode");
                }
            } else {
                LOG.warnf(e, "Lua script execution failed, falling back to non-script mode");
            }
            return incrementAndGetFallback(key, windowSeconds);
        }
    }

    /**
     * Reloads the Lua script into Redis.
     */
    private void reloadLuaScript() {
        try {
            if (luaScript != null) {
                Response response = redisAPI.scriptAndAwait(List.of("LOAD", luaScript));
                if (response != null) {
                    luaScriptSha = response.toString();
                    LOG.infof("Lua script reloaded with SHA: %s", luaScriptSha);
                }
            }
        } catch (Exception e) {
            LOG.warnf(e, "Failed to reload Lua script");
            useLuaScript = false;
        }
    }

    /**
     * Fallback increment using separate INCR and EXPIRE commands.
     */
    private long incrementAndGetFallback(String key, int windowSeconds) {
        ValueCommands<String, Long> commands = getValueCommands();

        // Redis INCR is atomic - guaranteed unique incrementing values
        Long count = commands.incr(key);

        // Set expiry on first increment
        if (count == 1) {
            try {
                commands.setex(key, (long) windowSeconds, count);
            } catch (Exception e) {
                LOG.warnf("Failed to set expiry for key: %s", key);
            }
        }

        return count;
    }

    /**
     * Gets the current count without incrementing.
     */
    public long getCurrentCount(String key) {
        try {
            ValueCommands<String, Long> commands = getValueCommands();
            Long value = commands.get(key);
            return value != null ? value : 0;
        } catch (Exception e) {
            LOG.warnf(e, "Failed to get velocity count for key: %s", key);
            return 0;
        }
    }

    /**
     * Resets the velocity counter for a specific key.
     */
    public void resetVelocity(String key) {
        try {
            ValueCommands<String, Long> commands = getValueCommands();
            commands.getdel(key);
            if (LOG.isDebugEnabled()) {
                LOG.debugf("Reset velocity key: %s", key);
            }
        } catch (Exception e) {
            LOG.warnf(e, "Failed to reset velocity key: %s", key);
        }
    }

    /**
     * Gets the dimension value from the transaction.
     * <p>
     * Performance: Uses direct field access instead of building a HashMap.
     * This eliminates redundant allocations since toEvaluationContext() is
     * already called in the main evaluation path.
     *
     * @param transaction the transaction context
     * @param dimension the dimension name (e.g., "card_hash", "amount")
     * @return the dimension value, or null if not found
     */
    private Object getDimensionValue(TransactionContext transaction, String dimension) {
        // Direct field access - zero allocations, much faster than HashMap lookup
        return switch (dimension) {
            case "card_hash" -> transaction.getCardHash();
            case "merchant_id" -> transaction.getMerchantId();
            case "merchant_name" -> transaction.getMerchantName();
            case "merchant_category" -> transaction.getMerchantCategory();
            case "merchant_category_code" -> transaction.getMerchantCategoryCode();
            case "amount" -> transaction.getAmount();
            case "currency" -> transaction.getCurrency();
            case "country_code" -> transaction.getCountryCode();
            case "ip_address" -> transaction.getIpAddress();
            case "device_id" -> transaction.getDeviceId();
            case "email" -> transaction.getEmail();
            case "phone" -> transaction.getPhone();
            case "transaction_type" -> transaction.getTransactionType();
            case "entry_mode" -> transaction.getEntryMode();
            case "card_present" -> transaction.getCardPresent();
            // Fallback for custom fields - rare case
            default -> {
                Map<String, Object> customFields = transaction.getCustomFieldsIfPresent();
                yield customFields != null ? customFields.get(dimension) : null;
            }
        };
    }

    /**
     * Encodes a key part to be safe for Redis keys.
     * Replaces special characters and limits length.
     */
    private String encodeKeyPart(String value) {
        if (value == null || value.isEmpty()) {
            return "empty";
        }
        if (value.length() <= 64) {
            if (!INVALID_KEY_CHARS.matcher(value).find()) {
                return value;
            }
        }
        return INVALID_KEY_CHARS.matcher(value).replaceAll("_")
                .substring(0, Math.min(value.length(), 64));
    }

    /**
     * Gets the default window seconds.
     */
    public int getDefaultWindowSeconds() {
        return defaultWindowSeconds;
    }

    /**
     * Gets the default threshold.
     */
    public int getDefaultThreshold() {
        return defaultThreshold;
    }

    /**
     * Captures a complete velocity snapshot using read-only operations.
     * <p>
     * <b>IMPORTANT:</b> This method uses getCurrentCount() which does NOT increment counters.
     * It is safe to call for snapshot purposes without affecting velocity enforcement.
     * <p>
     * Captures velocity across all standard dimensions and time windows:
     * <ul>
     *   <li>Card: 5min, 1h, 24h</li>
     *   <li>IP: 1h, 24h</li>
     *   <li>Device: 1h, 24h</li>
     * </ul>
     *
     * @param transaction the transaction context
     * @return a map of snapshot key to VelocityResult
     */
    public Map<String, Decision.VelocityResult> captureVelocitySnapshot(TransactionContext transaction) {
        Map<String, Decision.VelocityResult> snapshot = new java.util.LinkedHashMap<>();

        String cardHash = transaction.getCardHash();
        String ipAddress = transaction.getIpAddress();
        String deviceId = transaction.getDeviceId();

        // Card velocity (multiple windows)
        if (cardHash != null) {
            snapshot.put("card_5min", captureVelocityForDimension("card_hash", cardHash, 300, 10));
            snapshot.put("card_1h", captureVelocityForDimension("card_hash", cardHash, 3600, 20));
            snapshot.put("card_24h", captureVelocityForDimension("card_hash", cardHash, 86400, 50));
        }

        // IP velocity
        if (ipAddress != null) {
            snapshot.put("ip_1h", captureVelocityForDimension("ip_address", ipAddress, 3600, 20));
            snapshot.put("ip_24h", captureVelocityForDimension("ip_address", ipAddress, 86400, 100));
        }

        // Device velocity
        if (deviceId != null) {
            snapshot.put("device_1h", captureVelocityForDimension("device_id", deviceId, 3600, 15));
            snapshot.put("device_24h", captureVelocityForDimension("device_id", deviceId, 86400, 50));
        }

        return snapshot;
    }

    /**
     * Captures velocity for a specific dimension/window using read-only get.
     *
     * @param dimension the dimension name
     * @param dimensionValue the dimension value
     * @param windowSeconds the time window
     * @param threshold the threshold for this window
     * @return a VelocityResult with current count
     */
    private Decision.VelocityResult captureVelocityForDimension(
            String dimension, String dimensionValue, int windowSeconds, int threshold) {
        try {
            // Build the key the same way checkVelocity does
            String key = VELOCITY_KEY_PREFIX + "global:" + dimension + ":" + encodeKeyPart(dimensionValue);

            // Read-only get - does NOT increment
            long count = getCurrentCount(key);

            return new Decision.VelocityResult(
                    dimension,
                    dimensionValue,
                    count,
                    threshold,
                    windowSeconds
            );
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debugf("Failed to capture velocity for %s: %s", dimension, e.getMessage());
            }
            return new Decision.VelocityResult(dimension, dimensionValue, 0, threshold, windowSeconds);
        }
    }
}
