package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.user.EmailAddress;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;

import java.text.Normalizer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordPolicyTest {

    private static final EmailAddress EMAIL = EmailAddress.of("isuru.kavinda@example.com");
    private static final String BREACHED = "correct horse battery staple";

    // Fake breach list: only BREACHED is "known"; no network in unit tests
    private final PasswordPolicy policy = new PasswordPolicy(
            password -> new CompromisedPasswordDecision(BREACHED.equals(password)));

    @Test
    void acceptsFifteenCharacterPassword() {
        assertThat(policy.validate("abcdefghijklmno", EMAIL)).isEqualTo("abcdefghijklmno");
    }

    @Test
    void rejectsFourteenCharactersAsTooShort() {
        assertRejected("abcdefghijklmn", "TooShort");
    }

    @Test
    void countsUnicodeCodePointsNotJavaChars() {
        // 15 emoji = 15 code points but 30 Java chars: NIST counts code points
        String fifteenEmoji = "😀".repeat(15);

        assertThat(fifteenEmoji.length()).isEqualTo(30);
        assertThat(policy.validate(fifteenEmoji, EMAIL)).isEqualTo(fifteenEmoji);
    }

    @Test
    void acceptsSpacesAndAllowsExactly128() {
        assertThat(policy.validate("a b".repeat(42) + "ab", EMAIL)).hasSize(128);
    }

    @Test
    void rejects129CharactersAsTooLong() {
        assertRejected("a".repeat(129), "TooLong");
    }

    @Test
    void normalisesToNfcSoBothWaysOfTypingAnAccentAreEqual() {
        String composed = "café-password-long";                       // é as one code point
        String decomposed = Normalizer.normalize(composed, Normalizer.Form.NFD); // e + combining accent

        assertThat(decomposed).isNotEqualTo(composed);
        assertThat(policy.validate(decomposed, EMAIL)).isEqualTo(composed);
    }

    @Test
    void rejectsTheEmailAddressItself() {
        assertRejected("Isuru.Kavinda@Example.com", "ContextWord");
    }

    @Test
    void rejectsTheEmailLocalPartEvenWithDecoration() {
        assertRejected("Isuru.Kavinda-2026!!", "ContextWord");
    }

    @Test
    void rejectsTheServiceNameWithDigitsAndSymbols() {
        assertRejected("SwiftDrop2026!!!!!!", "ContextWord");
    }

    @Test
    void rejectsRepeatedServiceName() {
        assertRejected("swiftdrop swiftdrop", "ContextWord");
    }

    @Test
    void allowsPasswordThatOnlyContainsAContextWordAmongOtherWords() {
        assertThat(policy.validate("my swiftdrop parcel is late", EMAIL)).isNotNull();
    }

    @Test
    void rejectsBreachedPassword() {
        assertRejected(BREACHED, "Breached");
    }

    private void assertRejected(String password, String reason) {
        assertThatThrownBy(() -> policy.validate(password, EMAIL))
                .isInstanceOf(WeakPasswordException.class)
                .extracting("reason").isEqualTo(reason);
    }
}
