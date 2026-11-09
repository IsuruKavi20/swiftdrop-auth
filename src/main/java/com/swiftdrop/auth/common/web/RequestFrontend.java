package com.swiftdrop.auth.common.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Which registered frontend the CURRENT request came from: the browser's Origin header (set by the browser, not by
 * page code) matched exactly against {@link FrontendRegistry}. Null when there is no request (a background job), no
 * Origin (curl, server to server) or an unregistered one: links then go to the primary frontend. Host, Referer and
 * parameters are never used.
 */
@Component
public class RequestFrontend {

    private final FrontendRegistry frontends;

    public RequestFrontend(FrontendRegistry frontends) {
        this.frontends = frontends;
    }

    /** @return the frontend id, or null (= primary) */
    public String currentId() {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) {
            return null;
        }
        HttpServletRequest request = attributes.getRequest();
        return frontends.idForOrigin(request.getHeader(HttpHeaders.ORIGIN)).orElse(null);
    }
}
