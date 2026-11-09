package com.swiftdrop.auth.admin;

import com.swiftdrop.auth.audit.Actor;
import com.swiftdrop.auth.audit.AuditChecks;
import com.swiftdrop.auth.audit.AuditVerification;
import com.swiftdrop.auth.common.error.DomainException;
import com.swiftdrop.auth.user.RoleName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.ExitCodeGenerator;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.UUID;

/**
 * Identity step 9e: the break-glass tool's engine. deploy/oke/break-glass.ps1 starts this image once as a Kubernetes Job
 * with the "break-glass" profile and one command; it runs the SAME services as the admin portal (so every rule
 * holds: never the last admin, a reason is required, everything audited), as actor "break-glass", prints one result
 * line and exits. Only someone who can create Jobs in the cluster can use it: there is no web page to attack.
 * Prints ids, statuses and roles only: never emails, passwords or tokens.
 */
@Component
@Profile("break-glass")
class BreakGlassRunner implements ApplicationRunner {

    static final String RESULT = "BREAK-GLASS RESULT: ";
    static final String FAILED = "BREAK-GLASS FAILED: ";
    private static final Logger log = LoggerFactory.getLogger(BreakGlassRunner.class);

    private final AdminUsers adminUsers;
    private final RoleAdministration roles;
    private final AuditChecks auditChecks;
    private final ApplicationContext context;
    private final String command;
    private final String user;
    private final String role;
    private final String reason;
    private final boolean exitWhenDone;

    BreakGlassRunner(AdminUsers adminUsers, RoleAdministration roles, AuditChecks auditChecks,
                     ApplicationContext context,
                     @Value("${swiftdrop.break-glass.command:}") String command,
                     @Value("${swiftdrop.break-glass.user:}") String user,
                     @Value("${swiftdrop.break-glass.role:}") String role,
                     @Value("${swiftdrop.break-glass.reason:}") String reason,
                     @Value("${swiftdrop.break-glass.exit:true}") boolean exitWhenDone) {
        this.adminUsers = adminUsers;
        this.roles = roles;
        this.auditChecks = auditChecks;
        this.context = context;
        this.command = command;
        this.user = user;
        this.role = role;
        this.reason = reason;
        this.exitWhenDone = exitWhenDone;
    }

    @Override
    public void run(ApplicationArguments args) {
        int exitCode = 0;
        try {
            // The tool finds this line in the Job log (plain or JSON logs alike)
            log.warn("{}{}", RESULT, execute(command.toLowerCase(Locale.ROOT)));
        } catch (DomainException refused) {
            exitCode = 1;
            log.warn("{}{}", FAILED, refused.errorCode().name());
        } catch (IllegalArgumentException wrongInput) {
            exitCode = 2;
            log.warn("{}{}", FAILED, wrongInput.getMessage());
        }
        log.warn("Break-glass command={} finished exit={}", command, exitCode);
        if (exitWhenDone) {
            int code = exitCode;
            System.exit(SpringApplication.exit(context, (ExitCodeGenerator) () -> code));
        }
    }

    /** Package-private for the test. */
    String execute(String what) {
        Actor actor = Actor.breakGlass();
        return switch (what) {
            case "find" -> describe(user.contains("@") ? roles.findByEmail(user).id() : userId());
            case "block" -> describe(adminUsers.block(actor, userId(), reason));
            case "unblock" -> describe(adminUsers.unblock(actor, userId(), reason));
            case "end-sessions" -> describe(adminUsers.endSessions(actor, userId(), reason));
            case "delete" -> {
                adminUsers.delete(actor, userId(), reason);
                yield "deleted " + userId() + " (erasure started)";
            }
            case "grant" -> "roles of " + userId() + " now " + roles.grant(actor, userId(), roleName(), reason).roles();
            case "revoke" -> "roles of " + userId() + " now " + roles.revoke(actor, userId(), roleName(), reason).roles();
            case "verify" -> describe(auditChecks.verify());
            default -> throw new IllegalArgumentException("unknown command '" + what + "'");
        };
    }

    private String describe(UUID id) {
        return describe(adminUsers.detail(id));
    }

    private static String describe(AdminUsers.UserDetail detail) {
        return "user " + detail.id() + " status=" + detail.status() + " roles=" + detail.roles()
                + " sessions=" + detail.activeSessions();
    }

    private static String describe(AuditVerification result) {
        return result.ok()
                ? "audit chain OK, " + result.rowsChecked() + " rows, last seq " + result.lastSeq()
                : "AUDIT CHAIN BROKEN at seq " + result.firstBrokenSeq();
    }

    private UUID userId() {
        try {
            return UUID.fromString(user.strip());
        } catch (IllegalArgumentException notAnId) {
            throw new IllegalArgumentException("user must be an id (use 'find' first to get it)");
        }
    }

    private RoleName roleName() {
        try {
            return RoleName.valueOf(role.strip().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            throw new IllegalArgumentException("unknown role '" + role + "'");
        }
    }
}
