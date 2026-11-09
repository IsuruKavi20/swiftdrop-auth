package com.swiftdrop.auth.audit;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** An audit search or export with a bad filter: 400. */
public class InvalidAuditQueryException extends DomainException {

    public InvalidAuditQueryException() {
        super(ErrorCode.VALIDATION_FAILED);
    }
}
