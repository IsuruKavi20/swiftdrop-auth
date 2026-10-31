package com.swiftdrop.auth.login;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** One answer for unknown email, wrong password, locked and disabled: the caller can't tell which. */
public class InvalidCredentialsException extends DomainException {

    public InvalidCredentialsException() {
        super(ErrorCode.INVALID_CREDENTIALS);
    }
}
