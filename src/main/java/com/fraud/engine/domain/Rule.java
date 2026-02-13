package com.fraud.engine.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a fraud detection rule.
 *
 * A rule consists of:
 * - An ID that uniquely identifies the rule within a ruleset
 * - A name for display purposes
 * - Optional description explaining the rule
 * - Conditions that must ALL be true for the rule to match (AND logic)
 * - An action to take when the rule matches (APPROVE, DECLINE, REVIEW)
 * - Priority for ordering (higher = evaluated first)
 * - Velocity check configuration (optional)
 * - Optional compiled condition for high-performance evaluation
 * - Optional scope for rule bucketing
 * - Version metadata for hot reload tracking
 */
public class Rule {

    @NotBlank(message = "Rule ID is required")
    @JsonProperty("id")
    private String id;

    @NotBlank(message = "Rule name is required")
    @JsonProperty("name")
    private String name;

    @JsonProperty("description")
    private String description;

    @JsonProperty("conditions")
    private List<Condition> conditions = new ArrayList<>();

    @NotBlank(message = "Action is required")
    @JsonProperty("action")
    private String action;

    @JsonProperty("priority")
    @Positive(message = "Priority must be positive")
    private int priority = 0;

    @JsonProperty("velocity")
    private VelocityConfig velocity;

    @JsonProperty("enabled")
    private boolean enabled = true;

    @JsonProperty("compiled_condition")
    private transient CompiledCondition compiledCondition;

    @JsonProperty("scope")
    private RuleScope scope = RuleScope.GLOBAL;

    @JsonProperty("rule_version_id")
    private String ruleVersionId;

    @JsonProperty("rule_version")
    private Integer ruleVersion;

    public Rule() {
    }

    public Rule(String id, String name, String action) {
        this.id = id;
        this.name = name;
        this.action = action;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<Condition> getConditions() {
        return conditions;
    }

    public void setConditions(List<Condition> conditions) {
        this.conditions = conditions;
    }

    public void addCondition(Condition condition) {
        this.conditions.add(condition);
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public VelocityConfig getVelocity() {
        return velocity;
    }

    public void setVelocity(VelocityConfig velocity) {
        this.velocity = velocity;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public CompiledCondition getCompiledCondition() {
        return compiledCondition;
    }

    public void setCompiledCondition(CompiledCondition compiledCondition) {
        this.compiledCondition = compiledCondition;
    }

    public RuleScope getScope() {
        return scope;
    }

    public void setScope(RuleScope scope) {
        this.scope = scope;
    }

    public String getRuleVersionId() {
        return ruleVersionId;
    }

    public void setRuleVersionId(String ruleVersionId) {
        this.ruleVersionId = ruleVersionId;
    }

    public Integer getRuleVersion() {
        return ruleVersion;
    }

    public void setRuleVersion(Integer ruleVersion) {
        this.ruleVersion = ruleVersion;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Rule rule = (Rule) o;
        return Objects.equals(id, rule.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "Rule{" +
               "id='" + id + '\'' +
               ", name='" + name + '\'' +
               ", action='" + action + '\'' +
               ", priority=" + priority +
               ", enabled=" + enabled +
               ", conditionsCount=" + conditions.size() +
               '}';
    }

    /**
     * Checks if this rule matches the given transaction context.
     * All conditions must evaluate to true (AND logic).
     * <p>
     * Performance: Uses simple for-loop instead of Stream to avoid allocations
     * and enable better JIT inlining. Short-circuits on first failure.
     *
     * @param context the transaction context
     * @return true if all conditions match
     */
    public boolean matches(java.util.Map<String, Object> context) {
        if (!enabled || conditions == null || conditions.isEmpty()) {
            return false;
        }

        for (Condition condition : conditions) {
            if (!condition.evaluate(context)) {
                return false;
            }
        }
        return true;
    }

    public boolean matches(TransactionContext transaction) {
        if (!enabled) {
            return false;
        }
        if (compiledCondition != null) {
            return compiledCondition.matches(transaction);
        }
        return false;
    }

}
