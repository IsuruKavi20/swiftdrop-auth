package com.swiftdrop.auth.account;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** Unknown, used, expired, replaced, or no longer applicable: one answer for all, so a link reveals nothing. */
public class InvalidEmailChangeLinkException extends DomainException {

    public InvalidEmailChangeLinkException() {
        super(ErrorCode.INVALID_EMAIL_CHANGE_LINK);
    }
}
