package com.swiftdrop.auth.google;

import com.swiftdrop.auth.common.web.FrontendProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/** User pressed Cancel, Google returned an error, or state/nonce/ID-token checks failed. */
@Component
public class GoogleLoginFailureHandler implements AuthenticationFailureHandler {

    static final String ERROR_FRAGMENT = "error=login_failed";
    private static final Logger log = LoggerFactory.getLogger(GoogleLoginFailureHandler.class);

    private final FrontendProperties frontend;

    GoogleLoginFailureHandler(FrontendProperties frontend) {
        this.frontend = frontend;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        GoogleLoginSuccessHandler.endLoginSession(request);
        // The OAuth error code (e.g. access_denied, authorization_request_not_found) is safe to log: no personal data
        String reason = exception instanceof OAuth2AuthenticationException oauth
                ? oauth.getError().getErrorCode() : exception.getClass().getSimpleName();
        log.warn("Google login failed: reason={}", reason);
        response.sendRedirect(frontend.link(GoogleLoginSuccessHandler.CALLBACK_PATH + "#" + ERROR_FRAGMENT).toString());
    }
}
