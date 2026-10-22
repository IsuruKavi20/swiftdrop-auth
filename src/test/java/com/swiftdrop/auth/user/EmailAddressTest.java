package com.swiftdrop.auth.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EmailAddressTest {

    @Test
    void trimsAndLowercases() {
        assertThat(EmailAddress.of("  Isuru@X.COM ").value()).isEqualTo("isuru@x.com");
    }

    @Test
    void normalisesFullWidthLookAlikeCharacters() {
        // "ｉｓｕｒｕ" is full-width Unicode; NFKC turns it into plain "isuru"
        assertThat(EmailAddress.of("ｉｓｕｒｕ@x.com").value()).isEqualTo("isuru@x.com");
    }

    @Test
    void equalWhenSameNormalisedValue() {
        assertThat(EmailAddress.of("Isuru@X.com")).isEqualTo(EmailAddress.of("isuru@x.com"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            "   ",
            "no-at-sign.com",
            "two@@x.com",
            "a@b@c.com",
            "spaces in@x.com",
            "isuru@",
            "@x.com",
            "isuru@localhost",
            "isuru@-x.com",
            "isuru@x..com",
            "isurü@x.com",
            ".isuru@x.com",
            "isuru.@x.com",
            "is..uru@x.com"
    })
    void rejectsInvalidAddresses(String raw) {
        assertThatThrownBy(() -> EmailAddress.of(raw)).isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void rejectsLocalPartLongerThan64() {
        String raw = "a".repeat(65) + "@x.com";

        assertThatThrownBy(() -> EmailAddress.of(raw)).isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void rejectsAddressLongerThan320() {
        String raw = "a@" + (("b".repeat(60) + ".").repeat(6)) + "com";   // 371 characters

        assertThat(raw).hasSizeGreaterThan(320);

        assertThatThrownBy(() -> EmailAddress.of(raw)).isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void errorMessageNeverContainsTheAddress() {
        assertThatThrownBy(() -> EmailAddress.of("secret-person@@x.com"))
                .hasMessageNotContaining("secret-person");
    }

    @Test
    void rejectsHugeRawInputBeforeNormalising() {
        String raw = "a".repeat(10_000) + "@x.com";

        assertThatThrownBy(() -> EmailAddress.of(raw)).isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void toStringNeverRevealsTheAddress() {
        assertThat(EmailAddress.of("secret-person@x.com").toString()).doesNotContain("secret-person");
    }
}
