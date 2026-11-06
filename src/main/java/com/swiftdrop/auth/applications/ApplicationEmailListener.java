package com.swiftdrop.auth.applications;

import org.springframework.modulith.events.ApplicationModuleListener;
import org.springframework.stereotype.Component;

/** Sends the decision email AFTER the decision committed, asynchronously; failures stay in the outbox. */
@Component
class ApplicationEmailListener {

    private final RoleApplications applications;

    ApplicationEmailListener(RoleApplications applications) {
        this.applications = applications;
    }

    @ApplicationModuleListener
    void on(RoleApplicationDecided event) {
        applications.sendDecisionEmail(event.applicationId());
    }
}
