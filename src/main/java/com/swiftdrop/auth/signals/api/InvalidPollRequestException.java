package com.swiftdrop.auth.signals.api;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** A poll request with a malformed event id (400). */
class InvalidPollRequestException extends DomainException {

    InvalidPollRequestException() {
        super(ErrorCode.VALIDATION_FAILED);
    }
}
