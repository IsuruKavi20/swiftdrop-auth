package com.swiftdrop.auth.audit;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Identity step 9c: reading the audit log for the admin portal. Newest first, paged with a "before seq" bookmark
 * (stable while new rows arrive). Every filter is a bound parameter; the SQL text never contains caller input.
 */
@Service
public class AuditQueries {

    public static final int MAX_PAGE = 100;
    public static final int MAX_EXPORT = 10_000;
    private static final Pattern SAFE_FILTER = Pattern.compile("^[A-Za-z0-9_.:-]{1,80}$");

    private final JdbcTemplate jdbc;
    private final JsonMapper json;
    private final AuditLog audit;

    AuditQueries(JdbcTemplate jdbc, JsonMapper json, AuditLog audit) {
        this.jdbc = jdbc;
        this.json = json;
        this.audit = audit;
    }

    /** @throws InvalidAuditQueryException a filter that is not an id or action name, or from after to */
    public record Filter(String actor, String target, String action, Instant from, Instant to) {
        public Filter {
            for (String value : new String[] {actor, target, action}) {
                if (value != null && !SAFE_FILTER.matcher(value).matches()) {
                    throw new InvalidAuditQueryException();
                }
            }
            if (from != null && to != null && from.isAfter(to)) {
                throw new InvalidAuditQueryException();
            }
        }
    }

    public record Row(long seq, Instant at, String actorType, String actorId, String action, String targetType,
                      String targetId, String ip, String requestId, Map<String, Object> details) {
    }

    @Transactional(readOnly = true)
    public List<Row> search(Filter filter, Long beforeSeq, int limit) {
        if (limit < 1 || limit > MAX_PAGE) {
            throw new InvalidAuditQueryException();
        }
        List<Object> args = new ArrayList<>();
        StringBuilder where = where(filter, args);
        if (beforeSeq != null) {
            where.append(" AND seq < ?");
            args.add(beforeSeq);
        }
        args.add(limit);
        return jdbc.query("SELECT * FROM identity.audit_log WHERE " + where + " ORDER BY seq DESC LIMIT ?",
                rowMapper(), args.toArray());
    }

    /** The CSV download; the export itself is audited (who took a copy, of which period, how many rows). */
    @Transactional
    public String exportCsv(UUID adminId, Filter filter) {
        List<Object> args = new ArrayList<>();
        StringBuilder where = where(filter, args);
        args.add(MAX_EXPORT + 1);
        List<Row> rows = jdbc.query("SELECT * FROM identity.audit_log WHERE " + where + " ORDER BY seq LIMIT ?",
                rowMapper(), args.toArray());
        if (rows.size() > MAX_EXPORT) {
            throw new InvalidAuditQueryException();   // never a silently cut-off copy: choose a shorter period
        }
        audit.record(new AuditEntry(Actor.user(adminId), "audit.exported", null, null, Map.of(
                "from", String.valueOf(filter.from()), "to", String.valueOf(filter.to()), "rows", rows.size())));
        StringBuilder csv = new StringBuilder(
                "seq,at,actor_type,actor_id,action,target_type,target_id,ip,request_id,details\r\n");
        for (Row row : rows) {
            appendCsv(csv, row);
        }
        return csv.toString();
    }

    private static StringBuilder where(Filter filter, List<Object> args) {
        StringBuilder where = new StringBuilder("true");
        add(where, args, " AND actor_id = ?", filter.actor());
        add(where, args, " AND target_id = ?", filter.target());
        add(where, args, " AND action = ?", filter.action());
        add(where, args, " AND at >= ?", filter.from() == null ? null : Timestamp.from(filter.from()));
        add(where, args, " AND at < ?", filter.to() == null ? null : Timestamp.from(filter.to()));
        return where;
    }

    private static void add(StringBuilder where, List<Object> args, String condition, Object value) {
        if (value != null) {
            where.append(condition);
            args.add(value);
        }
    }

    private RowMapper<Row> rowMapper() {
        return (rs, n) -> new Row(rs.getLong("seq"), rs.getTimestamp("at").toInstant(), rs.getString("actor_type"),
                rs.getString("actor_id"), rs.getString("action"), rs.getString("target_type"),
                rs.getString("target_id"), rs.getString("ip"), rs.getString("request_id"),
                json.readValue(rs.getString("details"), new TypeReference<Map<String, Object>>() { }));
    }

    private void appendCsv(StringBuilder csv, Row row) {
        String[] fields = {Long.toString(row.seq()), row.at().toString(), row.actorType(), row.actorId(),
                row.action(), row.targetType(), row.targetId(), row.ip(), row.requestId(),
                json.writeValueAsString(row.details())};
        for (int i = 0; i < fields.length; i++) {
            csv.append(i == 0 ? "" : ",").append(csvField(fields[i]));
        }
        csv.append("\r\n");
    }

    /** Quoted; a leading = + - @ tab or CR is neutralised, so a spreadsheet never runs a cell as a formula. */
    static String csvField(String value) {
        if (value == null) {
            return "";
        }
        String safe = !value.isEmpty() && "=+-@\t\r".indexOf(value.charAt(0)) >= 0 ? "'" + value : value;
        return "\"" + safe.replace("\"", "\"\"") + "\"";
    }
}
