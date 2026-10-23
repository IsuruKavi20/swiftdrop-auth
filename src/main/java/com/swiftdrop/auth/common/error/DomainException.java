package com.swiftdrop.auth.common.error;

/**
 * Base class for business-rule failures. Features extend it and pick an {@link ErrorCode};
 * the global handler turns it into the matching Problem Details response.
 * The message is the code's fixed title, so it can never carry personal data.
 */
public abstract class DomainException extends RuntimeException {

    private final ErrorCode errorCode;

    protected DomainException(ErrorCode errorCode) {
        super(errorCode.title());
        this.errorCode = errorCode;
    }

    public ErrorCode errorCode() {
        return errorCode;
    }
}
