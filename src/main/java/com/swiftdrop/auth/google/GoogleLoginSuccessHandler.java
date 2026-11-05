package com.swiftdrop.auth.google;

import com.swiftdrop.auth.common.web.FrontendProperties;
import com.swiftdrop.auth.user.IdentityProfile;
import com.swiftdrop.auth.user.PicturePolicy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Spring has verified Google's ID token (signature, issuer, audience, expiry, nonce). We map it to our user,
 * end the short login session, and send the browser to the frontend with a one-time code in the fragment.
 */
@Component
public class GoogleLoginSuccessHandler implements AuthenticationSuccessHandler {

    static final String CALLBACK_PATH = "/auth/callback";
    static final String CHALLENGE_ATTRIBUTE = "swiftdrop.google.browser-challenge";
    private static final Logger log = LoggerFactory.getLogger(GoogleLoginSuccessHandler.class);

    private final GoogleAccountLinker linker;
    private final HandoffCodes handoffCodes;
    private final FrontendProperties frontend;
    private final PicturePolicy pictures;

    GoogleLoginSuccessHandler(GoogleAccountLinker linker, HandoffCodes handoffCodes, FrontendProperties frontend,
                              PicturePolicy pictures) {
        this.linker = linker;
        this.handoffCodes = handoffCodes;
        this.frontend = frontend;
        this.pictures = pictures;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String challenge = browserChallenge(request);
        endLoginSession(request);
        String fragment;
        try {
            if (challenge == null) {
                throw new GoogleLoginRefusedException("Login not started with a browser challenge");
            }
            OidcUser google = (OidcUser) authentication.getPrincipal();
            GoogleIdentity identity = new GoogleIdentity(google.getSubject(), google.getEmail(),
                    Boolean.TRUE.equals(google.getEmailVerified()), google.getClaimAsString("hd"),
                    pictures.trustedOnly(profileOf(google)));
            fragment = "code=" + handoffCodes.issue(linker.link(identity), challenge);
        } catch (RuntimeException refused) {
            // Refused account, or e.g. two first logins racing: details in our log, a generic error for the browser
            log.warn("Google login refused: reason={}", refused.getMessage());
            fragment = GoogleLoginFailureHandler.ERROR_FRAGMENT;
        }
        response.sendRedirect(frontend.link(CALLBACK_PATH + "#" + fragment).toString());
    }

    // Standard OIDC profile claims from the signed ID token; all optional, unusable values are dropped
    private static IdentityProfile profileOf(OidcUser google) {
        return IdentityProfile.fromProvider(google.getFullName(), google.getGivenName(), google.getFamilyName(),
                google.getPicture(), google.getLocale());
    }

    private static String browserChallenge(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        return session == null ? null : (String) session.getAttribute(CHALLENGE_ATTRIBUTE);
    }

    // The session only carried state/PKCE/nonce for the redirect; our API stays stateless
    static void endLoginSession(HttpServletRequest request) {
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }
}
