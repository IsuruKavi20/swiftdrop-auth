package com.swiftdrop.auth.login;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** Wrong current password, or a locked account: one answer for both (403, so the client keeps its session). */
public class ReauthenticationFailedException extends DomainException {

    public ReauthenticationFailedException() {
        super(ErrorCode.REAUTHENTICATION_FAILED);
    }
}
