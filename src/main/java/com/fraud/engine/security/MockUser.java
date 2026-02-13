package com.fraud.engine.security;

import java.util.Set;

public final class MockUser {

    public static final String SUB = "local-dev-user";
    public static final String GTY = "client-credentials";
    public static final String CLIENT_ID = "local-dev-client";
    public static final String ISSUER = "local-dev-issuer";

    public static final Set<String> ALL_SCOPES = Set.of(
        "execute:rules",
        "read:results",
        "replay:transactions",
        "read:metrics"
    );

    public static final String SCOPES_STRING = String.join(" ", ALL_SCOPES);

    private MockUser() {
    }
}
