package com.swiftdrop.auth.common.web;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

public class PayloadTooLargeException extends DomainException {

    public PayloadTooLargeException() {
        super(ErrorCode.PAYLOAD_TOO_LARGE);
    }
}
