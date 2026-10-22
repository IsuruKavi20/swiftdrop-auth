package com.swiftdrop.auth.user;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * A normalised, validated email address. If you hold one, it is trimmed, NFKC-normalised,
 * lowercase, plain ASCII and within RFC 5321 length limits.
 */
public record EmailAddress(String value) {

    private static final int MAX_LENGTH = 320;
    private static final int MAX_LOCAL_PART_LENGTH = 64;

    // ASCII only after NFKC: blocks look-alike (homoglyph) characters from other alphabets.
    // Local part: dot-separated words (no leading, trailing or double dots).
    // Domain needs at least one dot; each label 1-63 chars, no leading/trailing hyphen.
    private static final String LOCAL_WORD = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+";
    private static final Pattern FORMAT = Pattern.compile(
            "^" + LOCAL_WORD + "(?:\\." + LOCAL_WORD + ")*"
                    + "@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                    + "(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$");

    public EmailAddress {
        if (value == null || value.length() > MAX_LENGTH || !FORMAT.matcher(value).matches()
                || value.indexOf('@') > MAX_LOCAL_PART_LENGTH) {
            throw new InvalidEmailException();
        }
    }

    public static EmailAddress of(String raw) {
        // Reject oversized input before normalising: NFKC can expand one character into many
        if (raw == null || raw.length() > MAX_LENGTH * 2) {
            throw new InvalidEmailException();
        }
        String normalised = Normalizer.normalize(raw.trim(), Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
        return new EmailAddress(normalised);
    }

    /** Emails are personal data: never print them, even by accident in a log line. */
    @Override
    public String toString() {
        return "EmailAddress[redacted]";
    }
}
