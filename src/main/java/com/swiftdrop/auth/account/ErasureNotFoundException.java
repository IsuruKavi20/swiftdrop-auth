package com.swiftdrop.auth.account;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** A confirmation for an id that is neither a deleted account nor an already finished erasure. */
public class ErasureNotFoundException extends DomainException {

    public ErasureNotFoundException() {
        super(ErrorCode.ERASURE_NOT_FOUND);
    }
}
