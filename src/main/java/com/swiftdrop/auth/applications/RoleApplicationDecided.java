package com.swiftdrop.auth.applications;

import java.util.UUID;

/** Stored in the outbox with the decision: the applicant's email is sent after the commit, retried if it fails. */
record RoleApplicationDecided(UUID applicationId) {
}
