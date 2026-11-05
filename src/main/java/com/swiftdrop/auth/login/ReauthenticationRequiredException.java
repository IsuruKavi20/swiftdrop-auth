package com.swiftdrop.auth.login;

import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.common.error.ErrorCode;

/**
 * The account has no password to check (signed up with Google). Until it can prove itself another way
 * (a set-password flow or the OIDC auth_time of a fresh login, identity step 11), sensitive changes are refused.
 */
public class ReauthenticationRequiredException extends DomainException {

    public ReauthenticationRequiredException() {
        super(ErrorCode.REAUTHENTICATION_REQUIRED);
    }
}
