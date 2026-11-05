package com.swiftdrop.auth.user;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

public class InvalidPersonNameException extends DomainException {

    // The message is the error code's fixed title: never the name itself (personal data)
    public InvalidPersonNameException() {
        super(ErrorCode.INVALID_NAME);
    }
}
