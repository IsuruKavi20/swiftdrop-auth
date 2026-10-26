package com.swiftdrop.auth.security;

import java.text.Normalizer;

/** Shared password handling, so signup (hashing) and login (checking) treat input identically. */
public final class Passwords {

    private Passwords() {
    }

    /**
     * NFC makes the different byte forms of the same character equal (e.g. "é" typed as one or two
     * code points). Both signup and login must normalise like this before hashing or comparing.
     */
    public static String normalise(String rawPassword) {
        return Normalizer.normalize(rawPassword, Normalizer.Form.NFC);
    }
}
