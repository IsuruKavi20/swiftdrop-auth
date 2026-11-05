package com.swiftdrop.auth.account;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** The "new" address is the current one. Safe to say: the caller is logged in and knows their own address. */
public class EmailUnchangedException extends DomainException {

    public EmailUnchangedException() {
        super(ErrorCode.EMAIL_UNCHANGED);
    }
}
