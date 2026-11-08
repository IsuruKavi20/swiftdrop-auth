package com.swiftdrop.auth.applications;

/** Subjects of the role-application emails (also used by tests to find them in the inbox). */
final class ApplicationEmailSubjects {

    static final String APPROVED = "Your SwiftDrop role application was approved";
    static final String REJECTED = "Your SwiftDrop role application was not approved";

    private ApplicationEmailSubjects() {
    }
}
