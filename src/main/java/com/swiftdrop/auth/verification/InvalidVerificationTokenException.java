package com.swiftdrop.auth.verification;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** One answer for unknown, used and expired tokens alike: the client can't tell which. */
public class InvalidVerificationTokenException extends DomainException {

    public InvalidVerificationTokenException() {
        super(ErrorCode.INVALID_OR_EXPIRED_TOKEN);
    }
}
