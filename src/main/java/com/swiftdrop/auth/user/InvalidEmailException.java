package com.swiftdrop.auth.user;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

public class InvalidEmailException extends DomainException {

    // The message is the error code's fixed title: never the address itself (personal data)
    public InvalidEmailException() {
        super(ErrorCode.INVALID_EMAIL);
    }
}
