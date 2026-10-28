package com.swiftdrop.auth.google;

import com.swiftdrop.auth.common.crypto.OpaqueTokens;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Login-CSRF defence (RFC 9700 4.5, applied to our own hand-off): the browser that STARTS Google login sends
 * {@code code_challenge = base64url(SHA-256(verifier))}. We keep it in the login session; the hand-off code is
 * bound to it, and only that browser (which knows the verifier) can redeem the code. An attacker's code pushed
 * into a victim's browser is useless. Google never sees this value (Spring's own PKCE to Google is separate).
 */
class BrowserBoundAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    static final String CHALLENGE_PARAMETER = "code_challenge";

    private final OAuth2AuthorizationRequestResolver delegate;

    BrowserBoundAuthorizationRequestResolver(OAuth2AuthorizationRequestResolver delegate) {
        this.delegate = delegate;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return bind(request, delegate.resolve(request));
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return bind(request, delegate.resolve(request, clientRegistrationId));
    }

    private static OAuth2AuthorizationRequest bind(HttpServletRequest request, OAuth2AuthorizationRequest google) {
        if (google != null) {
            String challenge = request.getParameter(CHALLENGE_PARAMETER);
            if (OpaqueTokens.isWellFormed(challenge)) {
                request.getSession().setAttribute(GoogleLoginSuccessHandler.CHALLENGE_ATTRIBUTE, challenge);
            } else {
                // No (valid) binding: the success handler will refuse this login
                request.getSession().removeAttribute(GoogleLoginSuccessHandler.CHALLENGE_ATTRIBUTE);
            }
        }
        return google;
    }
}
