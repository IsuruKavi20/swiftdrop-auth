package com.swiftdrop.auth.google;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * The Google login session cookie, set explicitly: its security must never depend on which auto-configuration
 * applies (without this bean Spring Session can fall back to a plain "SESSION" cookie, no HttpOnly, no SameSite).
 * HttpOnly: scripts can't read it. SameSite=Lax: it comes back on Google's top-level redirect to our callback,
 * but not on cross-site sub-requests. Secure in prod (https only).
 */
@Configuration(proxyBeanMethods = false)
class LoginSessionCookieConfig {

    static final String COOKIE_NAME = "SWIFTDROP_LOGIN";

    @Bean
    CookieSerializer loginSessionCookie(@Value("${server.servlet.session.cookie.secure:false}") boolean secure) {
        DefaultCookieSerializer cookie = new DefaultCookieSerializer();
        cookie.setCookieName(COOKIE_NAME);
        cookie.setUseHttpOnlyCookie(true);
        cookie.setSameSite("Lax");
        cookie.setUseSecureCookie(secure);
        cookie.setCookiePath("/");
        return cookie;
    }
}
