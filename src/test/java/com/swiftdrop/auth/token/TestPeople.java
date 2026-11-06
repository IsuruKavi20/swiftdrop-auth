package com.swiftdrop.auth.token;

/** A stand-in person for tests that only need "some valid user token" (resource-server, admin, merchant tests). */
public final class TestPeople {

    public static final PersonClaims SOMEONE = new PersonClaims("someone@example.com", true, "Test User");

    private TestPeople() {
    }
}
