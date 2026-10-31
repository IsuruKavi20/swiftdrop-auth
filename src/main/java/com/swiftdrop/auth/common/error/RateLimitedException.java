package com.swiftdrop.auth.common.error;

/** 429 with a real Retry-After: how long until the caller's bucket has a token again. */
public class RateLimitedException extends DomainException {

    private final long retryAfterSeconds;

    public RateLimitedException(long retryAfterSeconds) {
        super(ErrorCode.RATE_LIMITED);
        this.retryAfterSeconds = Math.max(1, retryAfterSeconds);
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
