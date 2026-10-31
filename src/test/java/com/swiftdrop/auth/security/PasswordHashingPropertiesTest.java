package com.swiftdrop.auth.security;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordHashingPropertiesTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void owaspStrengthSettingsAreValid() {
        assertThat(validator.validate(new PasswordHashingProperties(16, 32, 2, 65_536, 2))).isEmpty();
    }

    @Test
    void memoryBelowOwaspMinimumIsRejected() {
        assertThat(validator.validate(new PasswordHashingProperties(16, 32, 1, 4_096, 2)))
                .extracting(violation -> violation.getPropertyPath().toString())
                .containsExactly("memoryKb");
    }

    @Test
    void singleIterationIsRejectedBecauseOwaspMinimumAssumesTwo() {
        assertThat(validator.validate(new PasswordHashingProperties(16, 32, 1, 19_456, 1)))
                .extracting(violation -> violation.getPropertyPath().toString())
                .containsExactly("iterations");
    }

    @Test
    void memoryAboveSafetyCapIsRejected() {
        assertThat(validator.validate(new PasswordHashingProperties(16, 32, 1, 1_048_576, 2)))
                .extracting(violation -> violation.getPropertyPath().toString())
                .containsExactly("memoryKb");
    }

    @Test
    void tooShortSaltAndZeroIterationsAreRejected() {
        assertThat(validator.validate(new PasswordHashingProperties(4, 32, 1, 65_536, 0)))
                .extracting(violation -> violation.getPropertyPath().toString())
                .containsExactlyInAnyOrder("saltLengthBytes", "iterations");
    }
}
