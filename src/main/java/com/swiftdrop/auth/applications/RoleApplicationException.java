package com.swiftdrop.auth.applications;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** A role application rule was broken (exists, already held, conflict, too soon, not found, closed). */
public class RoleApplicationException extends DomainException {

    public RoleApplicationException(ErrorCode code) {
        super(code);
    }
}
