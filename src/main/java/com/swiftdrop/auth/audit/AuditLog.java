package com.swiftdrop.auth.audit;

import com.swiftdrop.auth.common.concurrency.WriteOrder;
import com.swiftdrop.auth.common.error.ProblemDetails;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tools.jackson.databind.json.JsonMapper;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.TreeMap;

/**
 * Writes audit rows (identity step 9a), always inside the caller's transaction ({@code MANDATORY}): the action and
 * its row commit together, or neither does. Rows are numbered and chained under the shared write-order lock, so the
 * chain is built in commit order and two writers can never both link to the same previous row.
 */
@Service
public class AuditLog {

    private final JdbcTemplate jdbc;
    private final JsonMapper json;
    private final Clock clock;

    AuditLog(JdbcTemplate jdbc, JsonMapper json, Clock clock) {
        this.jdbc = jdbc;
        this.json = json;
        this.clock = clock;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void record(AuditEntry entry) {
        WriteOrder.lock(jdbc);
        long seq = jdbc.queryForObject("SELECT nextval('identity.audit_log_seq_seq')", Long.class);
        Instant at = AuditChain.storable(clock.instant());
        // Sorted keys: the same details always give the same text (and hash)
        String details = json.writeValueAsString(new TreeMap<>(entry.details()));
        AuditChain.Row row = new AuditChain.Row(seq, at, entry.actor().type().name(), entry.actor().id(),
                entry.action(), entry.targetType(), entry.targetId(), clientIp(), MDC.get(ProblemDetails.REQUEST_ID_KEY), details);
        String prevHash = lastHash();
        jdbc.update("INSERT INTO identity.audit_log (seq, at, actor_type, actor_id, action, target_type, target_id,"
                        + " ip, request_id, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                seq, Timestamp.from(at), row.actorType(), row.actorId(), row.action(), row.targetType(),
                row.targetId(), row.ip(), row.requestId(), details, prevHash, AuditChain.hash(prevHash, row));
    }

    private String lastHash() {
        return jdbc.queryForObject("SELECT coalesce((SELECT hash FROM identity.audit_log ORDER BY seq DESC LIMIT 1),"
                + " (SELECT hash FROM identity.audit_checkpoint WHERE id = 1))", String.class);
    }

    // Behind the load balancer prod takes this from the trusted proxy's header (server.forward-headers-strategy)
    private static String clientIp() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            HttpServletRequest request = attributes.getRequest();
            return request.getRemoteAddr();
        }
        return null;   // a scheduled job or the break-glass tool: no request
    }
}
