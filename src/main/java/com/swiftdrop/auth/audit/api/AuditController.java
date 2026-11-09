package com.swiftdrop.auth.audit.api;

import com.swiftdrop.auth.audit.AuditChecks;
import com.swiftdrop.auth.audit.AuditQueries;
import com.swiftdrop.auth.audit.AuditVerification;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.security.RequirePermission;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Identity step 9c: the audit log for the SwiftDrop admin portal (permission audit:read, ADMIN only). */
@RestController
@RequestMapping(ApiPaths.V1 + "/admin/audit")
public class AuditController {

    private static final MediaType CSV = new MediaType("text", "csv", StandardCharsets.UTF_8);

    private final AuditQueries queries;
    private final AuditChecks checks;

    AuditController(AuditQueries queries, AuditChecks checks) {
        this.queries = queries;
        this.checks = checks;
    }

    /** Newest first. Next page: pass the last row's seq as "before". */
    @GetMapping
    @RequirePermission("audit:read")
    public List<AuditQueries.Row> search(
            @RequestParam(required = false) String actor,
            @RequestParam(required = false) String target,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(required = false) Long before,
            @RequestParam(defaultValue = "50") int count) {
        return queries.search(new AuditQueries.Filter(actor, target, action, from, to), before, count);
    }

    @GetMapping("/export")
    @RequirePermission("audit:read")
    public ResponseEntity<String> export(
            @AuthenticationPrincipal Jwt caller,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to) {
        String csv = queries.exportCsv(callerId(caller), new AuditQueries.Filter(null, null, null, from, to));
        return ResponseEntity.ok().contentType(CSV)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"audit.csv\"")
                .body(csv);
    }

    @GetMapping("/verify")
    @RequirePermission("audit:read")
    public AuditVerification verify() {
        return checks.verify();
    }

    private static UUID callerId(Jwt caller) {
        try {
            return UUID.fromString(caller.getSubject());
        } catch (IllegalArgumentException notAUser) {
            // a merchant machine token (sub = mc_...) is not a person: 401, never a 500
            throw new BadCredentialsException("Not a user token");
        }
    }
}
