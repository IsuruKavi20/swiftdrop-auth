package com.swiftdrop.auth.verification;

import com.swiftdrop.auth.common.crypto.OpaqueTokens;

/** Email-link tokens: the shared opaque-token scheme (see {@link OpaqueTokens}). */
final class VerificationTokens {

    private VerificationTokens() {
    }

    static String newToken() {
        return OpaqueTokens.newToken();
    }

    static String hash(String token) {
        return OpaqueTokens.hash(token);
    }

    static boolean isWellFormed(String candidate) {
        return OpaqueTokens.isWellFormed(candidate);
    }
}
