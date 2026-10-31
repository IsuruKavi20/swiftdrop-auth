package com.swiftdrop.auth.merchant;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/** A merchant rule said no; the code says which (deep dive 25, section 3). */
public class MerchantException extends DomainException {

    MerchantException(ErrorCode code) {
        super(code);
    }
}
