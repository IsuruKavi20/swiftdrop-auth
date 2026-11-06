package com.swiftdrop.auth.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityProfileTest {

    @Test
    void keepsGoodProviderData() {
        IdentityProfile profile = IdentityProfile.fromProvider("Isuru Kavinda", "Isuru", "Kavinda",
                "https://lh3.googleusercontent.com/a/photo", "si-LK");

        assertThat(profile.name()).map(PersonName::value).contains("Isuru Kavinda");
        assertThat(profile.givenName()).map(PersonName::value).contains("Isuru");
        assertThat(profile.familyName()).map(PersonName::value).contains("Kavinda");
        assertThat(profile.pictureUrl()).contains("https://lh3.googleusercontent.com/a/photo");
        assertThat(profile.locale()).contains("si-LK");
    }

    @Test
    void missingProviderDataIsSimplyEmpty() {
        IdentityProfile profile = IdentityProfile.fromProvider(null, null, null, null, null);

        assertThat(profile.isEmpty()).isTrue();
    }

    @Test
    void badNameIsDroppedNotFatal() {
        IdentityProfile profile = IdentityProfile.fromProvider("Isuru\u202Eevil", null, null, null, null);

        assertThat(profile.name()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "http://lh3.googleusercontent.com/a/photo",   // not https
            "javascript:alert(1)",
            "data:image/png;base64,AAAA",
            "https://user:pass@example.com/x.png",          // credentials in the URL
            "https:///no-host",
            "HTTPS://lh3.googleusercontent.com/a/photo",  // the database only accepts lowercase https://
            "not a url"})
    void unsafePictureUrlsAreDropped(String url) {
        assertThat(IdentityProfile.fromProvider(null, null, null, url, null).pictureUrl()).isEmpty();
    }

    @Test
    void overlongPictureUrlIsDropped() {
        String longUrl = "https://example.com/" + "a".repeat(2100);

        assertThat(IdentityProfile.fromProvider(null, null, null, longUrl, null).pictureUrl()).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"en", "si-LK", "ta-LK", "en-GB", "zh-Hant-TW"})
    void acceptsLanguageTags(String tag) {
        assertThat(IdentityProfile.fromProvider(null, null, null, null, tag).locale()).contains(tag);
    }

    @Test
    void normalisesLanguageTagCase() {
        assertThat(IdentityProfile.fromProvider(null, null, null, null, "en_gb").locale()).contains("en-GB");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "x", "english please", "en-<script>", "123"})
    void dropsInvalidLanguageTags(String tag) {
        assertThat(IdentityProfile.fromProvider(null, null, null, null, tag).locale()).isEmpty();
    }

    @Test
    void ownProfileHoldsJustTheName() {
        IdentityProfile profile = IdentityProfile.ofName(PersonName.of("Nimal Perera"));

        assertThat(profile.name()).map(PersonName::value).contains("Nimal Perera");
        assertThat(profile.pictureUrl()).isEmpty();
    }
}
