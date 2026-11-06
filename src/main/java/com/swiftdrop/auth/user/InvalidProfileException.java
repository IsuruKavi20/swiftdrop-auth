package com.swiftdrop.auth.user;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;
import com.swiftdrop.auth.common.error.FieldViolation;

import java.util.List;

/** A profile field the user sent is not acceptable. Names the field and rule, never the value (personal data). */
public class InvalidProfileException extends DomainException {

    public InvalidProfileException(String field, String rule) {
        super(ErrorCode.INVALID_PROFILE, List.of(new FieldViolation(field, rule)));
    }
}
