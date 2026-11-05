package com.swiftdrop.auth.user;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** An edit without If-Match could silently overwrite a newer change, so it is refused (RFC 6585: 428). */
public class IfMatchRequiredException extends DomainException {

    public IfMatchRequiredException() {
        super(ErrorCode.PRECONDITION_REQUIRED);
    }
}
