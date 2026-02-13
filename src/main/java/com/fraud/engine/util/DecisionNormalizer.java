package com.fraud.engine.util;

import com.fraud.engine.domain.Decision;

public final class DecisionNormalizer {

    private DecisionNormalizer() {}

    public static String normalizeDecisionValue(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String upper = value.trim().toUpperCase();
        return switch (upper) {
            case "APPROVED", "ALLOW" -> Decision.DECISION_APPROVE;
            case "DECLINED", "BLOCK" -> Decision.DECISION_DECLINE;
            case "FLAG", "REVIEW" -> Decision.DECISION_REVIEW;
            default -> upper;
        };
    }

    public static String normalizeDecisionType(String value, String fallback) {
        String normalized = normalizeDecisionValue(value);
        if (Decision.DECISION_APPROVE.equals(normalized) ||
            Decision.DECISION_DECLINE.equals(normalized) ||
            Decision.DECISION_REVIEW.equals(normalized)) {
            return normalized;
        }
        return fallback;
    }

    public static String normalizeMONITORINGDecision(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim().toUpperCase();
        return switch (normalized) {
            case "APPROVE", "APPROVED", "ALLOW" -> Decision.DECISION_APPROVE;
            case "DECLINE", "DECLINED", "BLOCK" -> Decision.DECISION_DECLINE;
            default -> null;
        };
    }

    public static String normalizeAction(String action) {
        if (action == null || action.isBlank()) {
            return null;
        }
        return action.trim().toUpperCase();
    }

    public static String normalizeRuleAction(String action) {
        if (action == null || action.isBlank()) {
            return null;
        }
        String normalized = action.trim().toUpperCase();
        return switch (normalized) {
            case "APPROVE", "DECLINE", "REVIEW" -> normalized;
            case "APPROVED" -> "APPROVE";
            case "DECLINED" -> "DECLINE";
            case "ALLOW" -> "APPROVE";
            case "BLOCK" -> "DECLINE";
            case "FLAG" -> "REVIEW";
            default -> null;
        };
    }
}
