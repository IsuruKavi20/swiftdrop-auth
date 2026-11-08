package com.swiftdrop.auth.user;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Read access to the identity_events diary for other modules (delivery: identity step 6c/6d). The user module owns
 * the table; others read it only through here.
 */
@Component
public class IdentityEventLog {

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() { };
    private static final String COLUMNS = "id, seq, user_id, user_version, event_type, payload::text, occurred_at";

    private final JdbcTemplate jdbc;
    private final JsonMapper json;

    IdentityEventLog(JdbcTemplate jdbc, JsonMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    /** The newest line's number (0 when the diary is empty). */
    public long latestSeq() {
        Long latest = jdbc.queryForObject("SELECT COALESCE(MAX(seq), 0) FROM identity.identity_events", Long.class);
        return latest == null ? 0 : latest;
    }

    /** Lines written after {@code seq}, oldest first. */
    public List<StoredIdentityEvent> after(long seq, int limit) {
        return jdbc.query("SELECT " + COLUMNS + " FROM identity.identity_events WHERE seq > ? ORDER BY seq LIMIT ?",
                this::row, seq, limit);
    }

    public Optional<StoredIdentityEvent> byId(UUID id) {
        return jdbc.query("SELECT " + COLUMNS + " FROM identity.identity_events WHERE id = ?", this::row, id)
                .stream().findFirst();
    }

    private StoredIdentityEvent row(ResultSet rs, int rowNum) throws SQLException {
        return new StoredIdentityEvent(rs.getObject("id", UUID.class), rs.getLong("seq"),
                rs.getObject("user_id", UUID.class), rs.getLong("user_version"), rs.getString("event_type"),
                json.readValue(rs.getString("payload"), MAP), rs.getTimestamp("occurred_at").toInstant());
    }
}
