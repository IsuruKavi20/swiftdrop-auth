package com.swiftdrop.auth.google;

import com.swiftdrop.auth.common.crypto.OpaqueTokens;
import com.swiftdrop.auth.common.web.FrontendRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Login-CSRF defence (RFC 9700 4.5, applied to our own hand-off): the browser that STARTS Google login sends
 * {@code code_challenge = base64url(SHA-256(verifier))}. We keep it in the login session; the hand-off code is
 * bound to it, and only that browser (which knows the verifier) can redeem the code. An attacker's code pushed
 * into a victim's browser is useless. Google never sees this value (Spring's own PKCE to Google is separate).
 * Also remembers WHICH registered app started the login ({@code ?frontend=web}): an id, kept only if it is on the
 * list, so the user returns to that app. Never an address from the request (no open redirect).
 */
class BrowserBoundAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    static final String CHALLENGE_PARAMETER = "code_challenge";
    static final String FRONTEND_PARAMETER = "frontend";

    private final OAuth2AuthorizationRequestResolver delegate;
    private final FrontendRegistry frontends;

    BrowserBoundAuthorizationRequestResolver(OAuth2AuthorizationRequestResolver delegate, FrontendRegistry frontends) {
        this.delegate = delegate;
        this.frontends = frontends;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return bind(request, delegate.resolve(request));
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return bind(request, delegate.resolve(request, clientRegistrationId));
    }

    private OAuth2AuthorizationRequest bind(HttpServletRequest request, OAuth2AuthorizationRequest google) {
        if (google != null) {
            String challenge = request.getParameter(CHALLENGE_PARAMETER);
            if (OpaqueTokens.isWellFormed(challenge)) {
                request.getSession().setAttribute(GoogleLoginSuccessHandler.CHALLENGE_ATTRIBUTE, challenge);
            } else {
                // No (valid) binding: the success handler will refuse this login
                request.getSession().removeAttribute(GoogleLoginSuccessHandler.CHALLENGE_ATTRIBUTE);
            }
            String frontend = request.getParameter(FRONTEND_PARAMETER);
            if (frontends.isKnown(frontend)) {
                request.getSession().setAttribute(GoogleLoginSuccessHandler.FRONTEND_ATTRIBUTE, frontend);
            } else {
                // Unknown or missing: back to the primary app
                request.getSession().removeAttribute(GoogleLoginSuccessHandler.FRONTEND_ATTRIBUTE);
            }
            // Always show Google's account chooser (OIDC prompt=select_account). Without it, a browser that is signed
            // in to Google logs straight back into the same account, so "log out, then log in as someone else" fails.
            return OAuth2AuthorizationRequest.from(google)
                    .additionalParameters(parameters -> parameters.put("prompt", "select_account"))
                    .build();
        }
        return google;
    }
}
