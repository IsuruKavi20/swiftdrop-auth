package com.swiftdrop.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordEncoderTest {

    private static final PasswordHashingProperties SETTINGS = new PasswordHashingProperties(16, 32, 2, 65_536, 2);

    private final PasswordEncoder encoder = new PasswordEncoderConfig().passwordEncoder(SETTINGS);

    @Test
    void hashIsTaggedWithAlgorithmIdAndUsesArgon2id() {
        String hash = encoder.encode("correct horse battery staple");

        assertThat(hash).startsWith("{argon2}$argon2id$");
        assertThat(hash).doesNotContain("correct horse battery staple");
    }

    @Test
    void hashRecordsTheConfiguredCostSettings() {
        assertThat(encoder.encode("correct horse battery staple")).contains("m=65536,t=2,p=2");
    }

    @Test
    void matchesAcceptsRightPasswordAndRejectsWrongOne() {
        String hash = encoder.encode("correct horse battery staple");

        assertThat(encoder.matches("correct horse battery staple", hash)).isTrue();
        assertThat(encoder.matches("wrong password", hash)).isFalse();
    }

    @Test
    void samePasswordGivesDifferentHashesBecauseOfRandomSalt() {
        assertThat(encoder.encode("correct horse battery staple"))
                .isNotEqualTo(encoder.encode("correct horse battery staple"));
    }

    @Test
    void hashFromWeakerOldSettingsIsFlaggedForUpgrade() {
        String oldHash = "{argon2}" + new Argon2PasswordEncoder(16, 32, 1, 8_192, 1)
                .encode("correct horse battery staple");

        assertThat(encoder.matches("correct horse battery staple", oldHash)).isTrue();
        assertThat(encoder.upgradeEncoding(oldHash)).isTrue();
        assertThat(encoder.upgradeEncoding(encoder.encode("correct horse battery staple"))).isFalse();
    }
}
