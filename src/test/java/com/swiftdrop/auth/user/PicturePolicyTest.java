package com.swiftdrop.auth.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Photos are shown to other people: they may only come from trusted image hosts (no tracking pixels). */
class PicturePolicyTest {

    private final PicturePolicy policy = new PicturePolicy(
            new ProfileProperties(List.of(".googleusercontent.com", "images.swiftdrop.example")));

    @ParameterizedTest
    @ValueSource(strings = {
            "https://lh3.googleusercontent.com/a/photo",
            "https://lh6.googleusercontent.com/a-/x=s96-c",
            "https://LH3.GoogleUserContent.com/a/photo",       // host names are case-insensitive
            "https://images.swiftdrop.example/u/1.png"})
    void trustedHostsAreAccepted(String url) {
        assertThat(policy.isTrusted(url)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://tracker.example/pixel.png",                       // the attacker's own server
            "https://googleusercontent.com.evil.example/x.png",        // trusted name as a prefix
            "https://evilgoogleusercontent.com/x.png",                 // trusted name glued to another word
            "https://googleusercontent.com/x.png",                     // ".x" means sub-domains only
            "https://cdn.images.swiftdrop.example/x.png",              // exact host means exactly that host
            "https://lh3.googleusercontent.com:8443/x.png"})           // only the normal https port
    void everythingElseIsRefused(String url) {
        assertThat(policy.isTrusted(url)).isFalse();
    }

    @Test
    void userInputFromAnUntrustedHostIsAnError() {
        assertThatThrownBy(() -> policy.requireTrusted("https://tracker.example/pixel.png"))
                .isInstanceOf(InvalidProfileException.class);
        assertThat(policy.requireTrusted(null)).isNull();   // removing the photo is always allowed
    }

    @Test
    void providerDataFromAnUntrustedHostLosesOnlyThePicture() {
        IdentityProfile google = IdentityProfile.fromProvider("Isuru Kavinda", null, null,
                "https://tracker.example/pixel.png", "si-LK");

        IdentityProfile kept = policy.trustedOnly(google);

        assertThat(kept.pictureUrl()).isEmpty();
        assertThat(kept.name()).map(PersonName::value).contains("Isuru Kavinda");
        assertThat(kept.locale()).contains("si-LK");
    }

    @ParameterizedTest
    @ValueSource(strings = {"*", "*.example.com", "", " ", "https://example.com", "example.com/path", "."})
    void badHostRulesStopTheStart(String rule) {
        assertThatThrownBy(() -> new ProfileProperties(List.of(rule))).isInstanceOf(IllegalArgumentException.class);
    }
}
