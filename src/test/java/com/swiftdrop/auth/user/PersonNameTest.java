package com.swiftdrop.auth.user;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PersonNameTest {

    @Test
    void trimsAndCollapsesSpaces() {
        assertThat(PersonName.of("  Isuru   Kavinda \t").value()).isEqualTo("Isuru Kavinda");
    }

    @Test
    void normalisesToNfcSoTheSameNameIsStoredTheSameWay() {
        String decomposed = "Rene\u0301";   // e + combining accent
        assertThat(PersonName.of(decomposed).value()).isEqualTo("Ren\u00E9");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "ඉසුරු කවින්ද",          // Sinhala (uses ZWJ-free conjuncts)
            "ශ්\u200Dරී ලංකා",            // Sinhala with a zero-width joiner (U+200D)
            "இசுரு",                // Tamil
            "O'Brien-Smith Jr.",
            "José María"})
    void acceptsNamesInEveryScript(String name) {
        assertThat(PersonName.of(name).value()).isNotBlank();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\t"})
    void rejectsBlankNames(String blank) {
        assertThatThrownBy(() -> PersonName.of(blank)).isInstanceOf(InvalidPersonNameException.class);
    }

    @Test
    void rejectsNull() {
        assertThatThrownBy(() -> PersonName.of(null)).isInstanceOf(InvalidPersonNameException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "Isuru\u0000",        // NUL
            "Isuru\nAdmin",       // new line (log forging)
            "Isuru\u202Enimda",   // right-to-left override: displays differently from what is stored
            "Isuru\u2066x",       // bidi isolate
            "Isuru\u200Bx",       // zero-width space: invisible look-alike names
            "Isuru\uE000"})       // private-use character
    void rejectsHiddenAndControlCharacters(String sneaky) {
        assertThatThrownBy(() -> PersonName.of(sneaky)).isInstanceOf(InvalidPersonNameException.class);
    }

    @Test
    void rejectsLineAndParagraphSeparators() {
        assertThatThrownBy(() -> PersonName.of("Isuru\u2028x")).isInstanceOf(InvalidPersonNameException.class);
        assertThatThrownBy(() -> PersonName.of("Isuru\u2029x")).isInstanceOf(InvalidPersonNameException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "\u3164",          // Hangul filler: a letter that draws nothing
            "\uFFA0",          // half-width Hangul filler
            "\u2800",          // blank braille pattern
            "\u115F\u1160",    // Hangul choseong/jungseong fillers
            "\u200D",          // a lone joiner
            "\u0301\u0301",    // only combining accents, no letter
            "Isuru\uFE0F"})   // variation selector
    void rejectsNamesThatLookEmptyOrHideCharacters(String invisible) {
        assertThatThrownBy(() -> PersonName.of(invisible)).isInstanceOf(InvalidPersonNameException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"\u200DIsuru", "Isuru\u200D", "Isu\u200D\u200Dru", "Isu \u200Cru"})
    void joinersOnlyBetweenLetters(String misplaced) {
        assertThatThrownBy(() -> PersonName.of(misplaced)).isInstanceOf(InvalidPersonNameException.class);
    }

    @Test
    void theConstructorCannotSkipNormalising() {
        assertThat(new PersonName("  Isuru   Kavinda ").value()).isEqualTo("Isuru Kavinda");
        assertThat(new PersonName("Rene\u0301").value()).isEqualTo("Ren\u00E9");
    }

    @Test
    void limitsVisibleCharactersNotBytes() {
        String sinhalaLetter = "ක්\u200Dෂ";   // one visible cluster, several code points
        assertThat(PersonName.of("a".repeat(100)).value()).hasSize(100);
        assertThatThrownBy(() -> PersonName.of("a".repeat(101))).isInstanceOf(InvalidPersonNameException.class);
        assertThat(PersonName.of(sinhalaLetter.repeat(50)).value()).isNotBlank();
    }

    @Test
    void rejectsHugeInputBeforeDoingAnyWork() {
        assertThatThrownBy(() -> PersonName.of("a".repeat(100_000))).isInstanceOf(InvalidPersonNameException.class);
    }

    @Test
    void neverPrintsTheNameInLogs() {
        assertThat(PersonName.of("Isuru").toString()).doesNotContain("Isuru");
    }

    @Test
    void optionalVersionDropsBadInputInsteadOfFailing() {
        assertThat(PersonName.ofOptional("Isuru")).map(PersonName::value).contains("Isuru");
        assertThat(PersonName.ofOptional("bad\u202E")).isEmpty();
        assertThat(PersonName.ofOptional(null)).isEmpty();
    }
}
