package com.swiftdrop.auth.login;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** Only thrown after the CORRECT password, so it is only ever shown to someone who knows it. */
public class EmailNotVerifiedException extends DomainException {

    public EmailNotVerifiedException() {
        super(ErrorCode.EMAIL_NOT_VERIFIED);
    }
}
