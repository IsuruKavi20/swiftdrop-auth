package com.swiftdrop.auth.common.error;

import java.util.List;

/**
 * Base class for business-rule failures. Features extend it and pick an {@link ErrorCode};
 * the global handler turns it into the matching Problem Details response.
 * The message is the code's fixed title, so it can never carry personal data.
 */
public abstract class DomainException extends RuntimeException {

    private final ErrorCode errorCode;
    private final List<FieldViolation> violations;

    protected DomainException(ErrorCode errorCode) {
        this(errorCode, List.of());
    }

    /** For failures tied to specific request fields; they are listed in the response's errors[]. */
    protected DomainException(ErrorCode errorCode, List<FieldViolation> violations) {
        super(errorCode.title());
        this.errorCode = errorCode;
        this.violations = List.copyOf(violations);
    }

    public ErrorCode errorCode() {
        return errorCode;
    }

    public List<FieldViolation> violations() {
        return violations;
    }
}
