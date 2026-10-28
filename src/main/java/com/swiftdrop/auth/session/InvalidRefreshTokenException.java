package com.swiftdrop.auth.session;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** One answer for unknown, expired, used, revoked and blocked-account cases: nothing to learn from it. */
public class InvalidRefreshTokenException extends DomainException {

    public InvalidRefreshTokenException() {
        super(ErrorCode.INVALID_REFRESH_TOKEN);
    }
}
