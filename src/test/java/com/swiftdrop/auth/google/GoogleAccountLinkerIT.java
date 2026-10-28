package com.swiftdrop.auth.google;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.session.SessionService;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RoleRepository;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Every row of the account rules (deep dive 24, section 3), against the real database. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class GoogleAccountLinkerIT {

    @Autowired
    private GoogleAccountLinker linker;

    @Autowired
    private UserRepository users;

    @Autowired
    private RoleRepository roles;

    @Autowired
    private SessionService sessions;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void newGoogleUserGetsAVerifiedCustomerAccountWithoutPassword() {
        String email = uniqueEmail();

        UUID id = linker.link(GoogleIdentity.of(uniqueSub(), email, true));

        User user = users.findWithRolesById(id).orElseThrow();
        assertThat(user.getEmail()).isEqualTo(email);
        assertThat(user.isEmailVerified()).isTrue();
        assertThat(user.getPasswordHash()).isNull();
        assertThat(user.roleNames()).containsExactly("CUSTOMER");
    }

    @Test
    void returningGoogleUserIsFoundBySubEvenAfterChangingEmailAtGoogle() {
        String sub = uniqueSub();
        UUID first = linker.link(GoogleIdentity.of(sub, uniqueEmail(), true));

        UUID again = linker.link(GoogleIdentity.of(sub, uniqueEmail(), true));

        assertThat(again).isEqualTo(first);
    }

    @Test
    void verifiedPasswordAccountIsLinkedAndKeepsItsPassword() {
        String email = uniqueEmail();
        UUID existing = passwordUser(email, true);

        UUID id = linker.link(GoogleIdentity.of(uniqueSub(), email, true));

        assertThat(id).isEqualTo(existing);
        assertThat(users.findById(existing).orElseThrow().getPasswordHash()).isNotNull();
    }

    @Test
    void unverifiedPasswordAccountIsReclaimedPasswordWipedSessionsEnded() {
        String email = uniqueEmail();
        UUID existing = passwordUser(email, false);
        String attackerSession = transactions.execute(status ->
                sessions.start(users.findWithRolesById(existing).orElseThrow()).refreshToken());

        UUID id = linker.link(GoogleIdentity.of(uniqueSub(), email, true));

        User user = users.findById(existing).orElseThrow();
        assertThat(id).isEqualTo(existing);
        assertThat(user.getPasswordHash()).isNull();      // the pre-hijacker's password is gone
        assertThat(user.isEmailVerified()).isTrue();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity.refresh_tokens WHERE user_id = ? AND revoked_at IS NULL",
                Integer.class, existing)).isZero();       // and so are their sessions
        assertThat(attackerSession).isNotBlank();
    }

    @Test
    void googleAccountWithUnverifiedEmailIsRefused() {
        assertThatThrownBy(() -> linker.link(GoogleIdentity.of(uniqueSub(), uniqueEmail(), false)))
                .isInstanceOf(GoogleLoginRefusedException.class);
    }

    @Test
    void disabledAccountCannotLogInWithGoogle() {
        String email = uniqueEmail();
        String sub = uniqueSub();
        UUID id = linker.link(GoogleIdentity.of(sub, email, true));
        jdbc.update("UPDATE identity.users SET status = 'DISABLED' WHERE id = ?", id);

        assertThatThrownBy(() -> linker.link(GoogleIdentity.of(sub, email, true)))
                .isInstanceOf(GoogleLoginRefusedException.class);
    }

    @Test
    void accountAlreadyLinkedToAnotherGoogleAccountIsNotRelinked() {
        String email = uniqueEmail();
        linker.link(GoogleIdentity.of(uniqueSub(), email, true));

        assertThatThrownBy(() -> linker.link(GoogleIdentity.of(uniqueSub(), email, true)))
                .isInstanceOf(GoogleLoginRefusedException.class);
    }

    @Test
    void aWorkspaceEmailIsOnlyLinkedWhenGoogleConfirmsTheDomain() {
        String email = "staff-" + UUID.randomUUID().toString().substring(0, 8) + "@company.example";
        UUID existing = passwordUser(email, true);

        // Without hd, Google does not vouch that the company still controls that address (recycled domains)
        assertThatThrownBy(() -> linker.link(new GoogleIdentity(uniqueSub(), email, true, null)))
                .isInstanceOf(GoogleLoginRefusedException.class);

        assertThat(linker.link(new GoogleIdentity(uniqueSub(), email, true, "company.example"))).isEqualTo(existing);
    }

    @Test
    void rolesNeverComeFromGoogle() {
        String email = uniqueEmail();
        UUID existing = passwordUser(email, true);
        transactions.executeWithoutResult(status -> users.findById(existing).orElseThrow()
                .addRole(roles.findByName(RoleName.COURIER).orElseThrow()));

        UUID id = linker.link(GoogleIdentity.of(uniqueSub(), email, true));

        assertThat(users.findWithRolesById(id).orElseThrow().roleNames()).containsExactly("COURIER", "CUSTOMER");
    }

    private UUID passwordUser(String email, boolean verified) {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of(email), "{argon2}$argon2id$somebody-else");
            user.addRole(roles.findByName(RoleName.CUSTOMER).orElseThrow());
            if (verified) {
                user.markEmailVerified();
            }
            return users.saveAndFlush(user).getId();
        });
    }

    private static String uniqueEmail() {
        return "g-" + UUID.randomUUID().toString().substring(0, 8) + "@gmail.com";
    }

    private static String uniqueSub() {
        return String.valueOf(Math.abs(UUID.randomUUID().getMostSignificantBits()));
    }
}
