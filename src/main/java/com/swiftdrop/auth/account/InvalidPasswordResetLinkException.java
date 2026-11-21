package com.swiftdrop.auth.account;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** One answer for unknown, used and expired reset links alike: the client cannot tell which. */
public class InvalidPasswordResetLinkException extends DomainException {

    public InvalidPasswordResetLinkException() {
        super(ErrorCode.INVALID_OR_EXPIRED_TOKEN);
    }
}
