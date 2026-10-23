package com.swiftdrop.auth.signup;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

public class EmailAlreadyUsedException extends DomainException {

    public EmailAlreadyUsedException() {
        super(ErrorCode.EMAIL_ALREADY_USED);
    }
}
