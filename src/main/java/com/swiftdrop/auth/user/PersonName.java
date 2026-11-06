package com.swiftdrop.auth.user;

import java.text.BreakIterator;
import java.text.Normalizer;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A person's display name (OIDC {@code name}, {@code given_name}, {@code family_name}). If you hold one, it is
 * NFC-normalised, trimmed, single-spaced, 1-100 visible characters with at least one letter or digit, and free of
 * control, line-break, bidi and invisible characters. Every script is allowed: Sinhala and Tamil need the
 * zero-width joiners ZWJ/ZWNJ, so those stay, but only between letters.
 */
public record PersonName(String value) {

    private static final int MAX_GRAPHEMES = 100;
    // A visible character can be several code points (Sinhala conjuncts); the DB column holds 300
    private static final int MAX_CODE_POINTS = 300;
    private static final int MAX_RAW_LENGTH = MAX_CODE_POINTS * 4;
    private static final int ZWNJ = 0x200C;
    private static final int ZWJ = 0x200D;
    private static final Pattern SPACE_RUNS = Pattern.compile("\\p{Zs}+");
    // Characters that are letters or marks to Unicode but draw nothing: a name made of them looks empty
    private static final Set<Integer> BLANK_LOOKING = Set.of(
            0x034F,            // combining grapheme joiner
            0x115F, 0x1160,    // Hangul choseong / jungseong fillers
            0x17B4, 0x17B5,    // Khmer inherent vowels
            0x2800,            // braille blank
            0x3164, 0xFFA0);   // Hangul fillers

    /** Normalises here, so no way of creating a PersonName can skip the rules. */
    public PersonName {
        // Reject oversized input before normalising or scanning it
        if (value == null || value.length() > MAX_RAW_LENGTH) {
            throw new InvalidPersonNameException();
        }
        value = SPACE_RUNS.matcher(Normalizer.normalize(value, Normalizer.Form.NFC).strip()).replaceAll(" ");
        int[] codePoints = value.codePoints().toArray();
        if (codePoints.length == 0 || codePoints.length > MAX_CODE_POINTS || !allAllowed(codePoints)
                || value.codePoints().noneMatch(Character::isLetterOrDigit) || graphemes(value) > MAX_GRAPHEMES) {
            throw new InvalidPersonNameException();
        }
    }

    public static PersonName of(String raw) {
        return new PersonName(raw);
    }

    /** For data we don't control (e.g. Google's profile): bad or missing input is dropped, not an error. */
    public static Optional<PersonName> ofOptional(String raw) {
        try {
            return Optional.of(of(raw));
        } catch (InvalidPersonNameException unusable) {
            return Optional.empty();
        }
    }

    private static boolean allAllowed(int[] codePoints) {
        for (int i = 0; i < codePoints.length; i++) {
            if (!isAllowed(codePoints, i)) {
                return false;
            }
        }
        return true;
    }

    // Refused: control (Cc), line/paragraph separators (Zl/Zp), format (Cf: bidi overrides, zero-width space),
    // private use, unassigned, lone surrogates, variation selectors and blank-looking letters. Joiners are only
    // allowed where Indic spelling needs them: after a letter or mark and before a letter.
    private static boolean isAllowed(int[] codePoints, int index) {
        int codePoint = codePoints[index];
        if (BLANK_LOOKING.contains(codePoint) || isVariationSelector(codePoint)) {
            return false;
        }
        return switch (Character.getType(codePoint)) {
            case Character.CONTROL, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR, Character.PRIVATE_USE,
                 Character.UNASSIGNED, Character.SURROGATE -> false;
            case Character.FORMAT -> (codePoint == ZWJ || codePoint == ZWNJ) && isBetweenLetters(codePoints, index);
            default -> true;
        };
    }

    private static boolean isBetweenLetters(int[] codePoints, int index) {
        return index > 0 && index < codePoints.length - 1
                && isLetterOrMark(codePoints[index - 1]) && Character.isLetter(codePoints[index + 1]);
    }

    private static boolean isLetterOrMark(int codePoint) {
        int type = Character.getType(codePoint);
        return Character.isLetter(codePoint) || type == Character.NON_SPACING_MARK
                || type == Character.COMBINING_SPACING_MARK || type == Character.ENCLOSING_MARK;
    }

    private static boolean isVariationSelector(int codePoint) {
        return codePoint >= 0xFE00 && codePoint <= 0xFE0F || codePoint >= 0xE0100 && codePoint <= 0xE01EF;
    }

    private static int graphemes(String text) {
        BreakIterator clusters = BreakIterator.getCharacterInstance();
        clusters.setText(text);
        int count = 0;
        while (clusters.next() != BreakIterator.DONE) {
            count++;
        }
        return count;
    }

    /** Names are personal data: never print them, even by accident in a log line. */
    @Override
    public String toString() {
        return "PersonName[redacted]";
    }
}
