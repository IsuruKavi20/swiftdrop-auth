package com.swiftdrop.auth.google;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** Unknown, expired, already used, or the account can no longer log in: one answer for all. */
public class InvalidLoginCodeException extends DomainException {

    public InvalidLoginCodeException() {
        super(ErrorCode.INVALID_LOGIN_CODE);
    }
}
