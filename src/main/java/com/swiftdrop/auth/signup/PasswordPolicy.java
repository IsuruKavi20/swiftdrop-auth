package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.user.EmailAddress;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * NIST SP 800-63B-4 password rules for password-only accounts: 15 to 128 characters counted as
 * Unicode code points, no composition rules, not a context-specific word, not in a known breach.
 */
@Component
public class PasswordPolicy {

    public static final int MIN_LENGTH = 15;
    public static final int MAX_LENGTH = 128;

    private static final String SERVICE_NAME = "swiftdrop";
    private static final Pattern NON_LETTERS = Pattern.compile("[^\\p{L}]");

    private final CompromisedPasswordChecker breachedPasswords;

    public PasswordPolicy(CompromisedPasswordChecker breachedPasswords) {
        this.breachedPasswords = breachedPasswords;
    }

    /** Returns the normalised password (the form that must be hashed) or throws with the reason. */
    public String validate(String rawPassword, EmailAddress email) {
        if (rawPassword == null) {
            throw new WeakPasswordException("TooShort");
        }
        String password = normalise(rawPassword);
        int length = password.codePointCount(0, password.length());
        if (length < MIN_LENGTH) {
            throw new WeakPasswordException("TooShort");
        }
        if (length > MAX_LENGTH) {
            throw new WeakPasswordException("TooLong");
        }
        if (isContextWord(password, email)) {
            throw new WeakPasswordException("ContextWord");
        }
        if (breachedPasswords.check(password).isCompromised()) {
            throw new WeakPasswordException("Breached");
        }
        return password;
    }

    /**
     * NFC makes the different byte forms of the same character equal (e.g. "é" typed as one or two
     * code points). Login must normalise the same way before comparing hashes.
     */
    public static String normalise(String rawPassword) {
        return Normalizer.normalize(rawPassword, Normalizer.Form.NFC);
    }

    // "SwiftDrop2026!!" or "isuru.kavinda-isuru.kavinda" are just the service name / username decorated
    private static boolean isContextWord(String password, EmailAddress email) {
        String letters = lettersOnly(password);
        if (letters.isEmpty()) {
            return false;
        }
        String address = email.value();
        String localPart = lettersOnly(address.substring(0, address.indexOf('@')));
        return letters.equals(lettersOnly(address))
                || isRepetitionOf(letters, SERVICE_NAME)
                || isRepetitionOf(letters, localPart);
    }

    private static String lettersOnly(String text) {
        return NON_LETTERS.matcher(text.toLowerCase(Locale.ROOT)).replaceAll("");
    }

    private static boolean isRepetitionOf(String text, String word) {
        return !word.isEmpty()
                && text.length() % word.length() == 0
                && word.repeat(text.length() / word.length()).equals(text);
    }
}
