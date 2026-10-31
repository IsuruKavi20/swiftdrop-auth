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
    private static final int MAX_DETAIL_LENGTH = 200;
    private static final Logger log = LoggerFactory.getLogger(GoogleLoginFailureHandler.class);

    private final FrontendProperties frontend;

    GoogleLoginFailureHandler(FrontendProperties frontend) {
        this.frontend = frontend;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        GoogleLoginSuccessHandler.endLoginSession(request);
        // The OAuth error code and Google's fixed technical description (e.g. "Missing parameter: code_verifier")
        // carry no personal data; the description is shortened and stripped of line breaks (no log injection)
        String reason = exception.getClass().getSimpleName();
        String detail = "";
        if (exception instanceof OAuth2AuthenticationException oauth) {
            reason = oauth.getError().getErrorCode();
            detail = safeForLog(oauth.getError().getDescription());
        }
        log.warn("Google login failed: reason={} detail={}", reason, detail);
        response.sendRedirect(frontend.link(GoogleLoginSuccessHandler.CALLBACK_PATH + "#" + ERROR_FRAGMENT).toString());
    }

    private static String safeForLog(String text) {
        if (text == null) {
            return "";
        }
        String oneLine = text.replaceAll("[\\r\\n\\t]", " ");
        return oneLine.length() > MAX_DETAIL_LENGTH ? oneLine.substring(0, MAX_DETAIL_LENGTH) : oneLine;
    }
}
