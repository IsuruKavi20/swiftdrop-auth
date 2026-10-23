package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;
import com.swiftdrop.auth.common.error.FieldViolation;

import java.util.List;

/**
 * The password breaks a rule. NIST SP 800-63B-4 requires telling the user why, so the reason
 * (TooShort, TooLong, ContextWord, Breached) is returned; the password itself never is.
 */
public class WeakPasswordException extends DomainException {

    private final String reason;

    public WeakPasswordException(String reason) {
        super(ErrorCode.WEAK_PASSWORD, List.of(new FieldViolation("password", reason)));
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
