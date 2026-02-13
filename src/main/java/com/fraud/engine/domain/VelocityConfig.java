package com.fraud.engine.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Velocity configuration for a fraud detection rule.
 * <p>
 * Velocity rules track transaction frequency within a time window to detect
 * patterns like rapid successive transactions from the same card.
 * <p>
 * When a rule has velocity configured, the system checks if the velocity
 * threshold has been exceeded before applying the rule action.
 * <p>
 * This is a shared class used by both {@link Rule} and
 * {@link com.fraud.engine.domain.compiled.CompiledRule} to ensure
 * consistency across the codebase.
 */
public class VelocityConfig {

    @JsonProperty("dimension")
    private String dimension;

    @JsonProperty("window_seconds")
    private int windowSeconds = 3600;

    @JsonProperty("threshold")
    private int threshold = 10;

    @JsonProperty("action")
    private String action;

    /**
     * Default constructor for JSON deserialization.
     */
    public VelocityConfig() {
    }

    /**
     * Constructor with all fields.
     *
     * @param dimension     the velocity dimension (e.g., "card_hash", "merchant_id")
     * @param windowSeconds the time window in seconds
     * @param threshold     the count threshold
     * @param action        the action to take when threshold is exceeded
     */
    public VelocityConfig(String dimension, int windowSeconds, int threshold, String action) {
        this.dimension = dimension;
        this.windowSeconds = windowSeconds;
        this.threshold = threshold;
        this.action = action;
    }

    /**
     * Constructor without action (for backward compatibility).
     *
     * @param dimension     the velocity dimension
     * @param windowSeconds the time window in seconds
     * @param threshold     the count threshold
     */
    public VelocityConfig(String dimension, int windowSeconds, int threshold) {
        this(dimension, windowSeconds, threshold, null);
    }

    public String getDimension() {
        return dimension;
    }

    public void setDimension(String dimension) {
        this.dimension = dimension;
    }

    public int getWindowSeconds() {
        return windowSeconds;
    }

    public void setWindowSeconds(int windowSeconds) {
        this.windowSeconds = windowSeconds;
    }

    public int getThreshold() {
        return threshold;
    }

    public void setThreshold(int threshold) {
        this.threshold = threshold;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    @Override
    public String toString() {
        return "VelocityConfig{" +
                "dimension='" + dimension + '\'' +
                ", windowSeconds=" + windowSeconds +
                ", threshold=" + threshold +
                ", action='" + action + '\'' +
                '}';
    }
}
