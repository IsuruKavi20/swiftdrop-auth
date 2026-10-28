package com.swiftdrop.auth.google;

/** A Google login we won't accept. The reason is for our logs only; the browser always sees "login_failed". */
public class GoogleLoginRefusedException extends RuntimeException {

    GoogleLoginRefusedException(String reason) {
        super(reason);
    }
}
