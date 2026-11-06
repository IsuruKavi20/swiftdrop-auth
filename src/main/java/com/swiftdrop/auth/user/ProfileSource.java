package com.swiftdrop.auth.user;

/** Who wrote the identity profile last. The user's own edits are never overwritten by a provider. */
public enum ProfileSource {
    USER,
    GOOGLE
}
