package com.swiftdrop.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordEncoderTest {

    private final PasswordEncoder encoder = new SecurityConfig().passwordEncoder();

    @Test
    void hashUsesArgon2idAndNeverContainsThePlainPassword() {
        String hash = encoder.encode("correct horse battery staple");

        assertThat(hash).startsWith("$argon2id$");
        assertThat(hash).doesNotContain("correct horse battery staple");
    }

    @Test
    void matchesAcceptsRightPasswordAndRejectsWrongOne() {
        String hash = encoder.encode("correct horse battery staple");

        assertThat(encoder.matches("correct horse battery staple", hash)).isTrue();
        assertThat(encoder.matches("wrong password", hash)).isFalse();
    }

    @Test
    void samePasswordGivesDifferentHashesBecauseOfRandomSalt() {
        String first = encoder.encode("correct horse battery staple");
        String second = encoder.encode("correct horse battery staple");

        assertThat(first).isNotEqualTo(second);
    }
}
