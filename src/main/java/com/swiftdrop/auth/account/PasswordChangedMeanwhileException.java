package com.swiftdrop.auth.account;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** Two password changes at the same moment: only the first wins, the other must start again (409). */
public class PasswordChangedMeanwhileException extends DomainException {

    public PasswordChangedMeanwhileException() {
        super(ErrorCode.CONFLICT);
    }
}
