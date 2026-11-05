package com.swiftdrop.auth.user;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** The profile changed since the client read it (If-Match no longer matches): reload instead of overwriting. */
public class ProfileChangedException extends DomainException {

    public ProfileChangedException() {
        super(ErrorCode.PRECONDITION_FAILED);
    }
}
