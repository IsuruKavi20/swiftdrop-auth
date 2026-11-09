package com.swiftdrop.auth.common.web;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The registered frontends (the SwiftDrop app online, on laptops): the ONLY places users are ever sent to. A request
 * may name one (an id) or come from one (an exact Origin); it can never supply an address (no open redirect).
 */
class FrontendRegistryTest {

    private final FrontendRegistry registry = new FrontendRegistry(List.of(
            frontend("local", "http://localhost:5173", true),
            frontend("web", "https://app.getswiftdrop.me", false)));

    @Test
    void linksGoToTheNamedApp() {
        assertThat(registry.link("web", "/auth/callback"))
                .isEqualTo(URI.create("https://app.getswiftdrop.me/auth/callback"));
        assertThat(registry.link("local", "/verify-email#token=abc"))
                .isEqualTo(URI.create("http://localhost:5173/verify-email#token=abc"));
    }

    @Test
    void unknownFrontendIdFallsBackToPrimary() {
        assertThat(registry.link("evil", "/x")).isEqualTo(URI.create("http://localhost:5173/x"));
        assertThat(registry.link("https://evil.example", "/x")).isEqualTo(URI.create("http://localhost:5173/x"));
    }

    @Test
    void oldTokensWithoutFrontendUsePrimary() {
        assertThat(registry.link(null, "/login")).isEqualTo(URI.create("http://localhost:5173/login"));
    }

    @Test
    void anOriginOnlyCountsWhenItMatchesExactly() {
        assertThat(registry.idForOrigin("https://app.getswiftdrop.me")).contains("web");
        assertThat(registry.idForOrigin("http://localhost:5173")).contains("local");
    }

    @Test
    void originNotOnTheListGetsPrimary() {
        // Look-alikes: a longer host, user info, another port, http instead of https, a trailing slash
        for (String origin : List.of("https://app.getswiftdrop.me.evil.com", "https://app.getswiftdrop.me@evil.com",
                "https://app.getswiftdrop.me:8443", "http://app.getswiftdrop.me", "https://app.getswiftdrop.me/",
                "null", "")) {
            assertThat(registry.idForOrigin(origin)).as(origin).isEmpty();
        }
        assertThat(registry.idForOrigin(null)).isEmpty();
    }

    @Test
    void corsOriginsAreExactlyTheRegisteredApps() {
        assertThat(registry.origins()).containsExactly("http://localhost:5173", "https://app.getswiftdrop.me");
    }

    @Test
    void httpOnlyForLocalhost() {
        assertThatThrownBy(() -> single("http://app.getswiftdrop.me")).isInstanceOf(IllegalArgumentException.class);
        assertThat(single("http://127.0.0.1:3000").origins()).containsExactly("http://127.0.0.1:3000");
    }

    @Test
    void onlyABareAddressWithoutUserInfoPathOrWildcard() {
        for (String bad : List.of("https://evil@app.getswiftdrop.me", "https://app.getswiftdrop.me/app",
                "https://app.getswiftdrop.me?x=1", "https://*.getswiftdrop.me", "app.getswiftdrop.me")) {
            assertThatThrownBy(() -> single(bad)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void writtenTheWayBrowsersSendTheOrigin() {
        // Browsers send lowercase and leave out the default port: these would silently never match
        for (String bad : List.of("https://App.GetSwiftDrop.me", "https://app.getswiftdrop.me:443", "HTTPS://app.getswiftdrop.me")) {
            assertThatThrownBy(() -> single(bad)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void onePrimaryRequired() {
        assertThatThrownBy(() -> new FrontendRegistry(List.of(frontend("local", "http://localhost:5173", false))))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new FrontendRegistry(List.of(frontend("local", "http://localhost:5173", true),
                frontend("web", "https://app.getswiftdrop.me", true)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new FrontendRegistry(List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new FrontendRegistry(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void idsAreShortSimpleAndUnique() {
        assertThatThrownBy(() -> new FrontendRegistry(List.of(frontend("web", "https://a.getswiftdrop.me", true),
                frontend("web", "https://b.getswiftdrop.me", false)))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new FrontendRegistry(List.of(frontend("Web App!", "https://a.getswiftdrop.me", true))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static FrontendRegistry single(String baseUrl) {
        return new FrontendRegistry(List.of(frontend("only", baseUrl, true)));
    }

    private static FrontendRegistry.Frontend frontend(String id, String baseUrl, boolean primary) {
        return new FrontendRegistry.Frontend(id, URI.create(baseUrl), primary);
    }
}
