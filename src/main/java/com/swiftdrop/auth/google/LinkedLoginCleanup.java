package com.swiftdrop.auth.google;

import com.swiftdrop.auth.user.AccountDeleted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.modulith.events.ApplicationModuleListener;
import org.springframework.stereotype.Component;

/**
 * A deleted account loses its Google link, so the same Google account can later sign up afresh (the old link would
 * otherwise point at the tombstone and refuse every login).
 */
@Component
class LinkedLoginCleanup {

    private static final Logger log = LoggerFactory.getLogger(LinkedLoginCleanup.class);

    private final OAuthAccountRepository accounts;

    LinkedLoginCleanup(OAuthAccountRepository accounts) {
        this.accounts = accounts;
    }

    // @ApplicationModuleListener = after commit, async, in its own new transaction (no extra @Transactional)
    @ApplicationModuleListener
    void on(AccountDeleted event) {
        int removed = accounts.deleteByUserId(event.userId());
        log.info("Linked logins removed for deleted account user={} count={}", event.userId(), removed);
    }
}
