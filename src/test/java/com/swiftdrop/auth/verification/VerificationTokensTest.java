package com.swiftdrop.auth.verification;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationTokensTest {

    @Test
    void tokenIs43UrlSafeCharactersFrom256RandomBits() {
        assertThat(VerificationTokens.newToken()).matches("^[A-Za-z0-9_-]{43}$");
    }

    @Test
    void tokensAreUnique() {
        Set<String> tokens = new HashSet<>();
        for (int i = 0; i < 1_000; i++) {
            tokens.add(VerificationTokens.newToken());
        }
        assertThat(tokens).hasSize(1_000);
    }

    @Test
    void hashIsSha256HexAndDeterministic() {
        // SHA-256("abc") test vector from FIPS 180-2
        assertThat(VerificationTokens.hash("abc"))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void wellFormedCheckRejectsAnythingThatIsNotAToken() {
        assertThat(VerificationTokens.isWellFormed(VerificationTokens.newToken())).isTrue();
        assertThat(VerificationTokens.isWellFormed("short")).isFalse();
        assertThat(VerificationTokens.isWellFormed("a".repeat(42) + "!")).isFalse();
        assertThat(VerificationTokens.isWellFormed(null)).isFalse();
    }
}
