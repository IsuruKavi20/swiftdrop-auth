package com.swiftdrop.auth.signals;

import com.swiftdrop.auth.token.SecurityEventTokenIssuer;
import com.swiftdrop.auth.user.IdentityEventLog;
import com.swiftdrop.auth.user.StoredIdentityEvent;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Poll-based delivery (RFC 8936; identity step 6d): the receiver confirms what it got ({@code ack}), reports SETs it
 * couldn't use ({@code setErrs}), and collects what is waiting. Waiting = PENDING and DEAD (pushing gave up), never
 * DELIVERED or REJECTED. A receiver only ever touches its own rows.
 */
@Component
public class EventPolling {

    private static final int MAX_ERROR_LENGTH = 200;

    private final EventsProperties settings;
    private final EventDelivery delivery;
    private final IdentityEventLog diary;
    private final SecurityEventTokenIssuer sets;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final Clock clock;

    EventPolling(EventsProperties settings, EventDelivery delivery, IdentityEventLog diary,
                 SecurityEventTokenIssuer sets, JdbcTemplate jdbc, TransactionTemplate transactions, Clock clock) {
        this.settings = settings;
        this.delivery = delivery;
        this.diary = diary;
        this.sets = sets;
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.clock = clock;
    }

    /** The configured receiver with this id, if any. */
    public java.util.Optional<EventsProperties.Receiver> receiver(String id) {
        return settings.receivers().stream().filter(receiver -> receiver.id().equals(id)).findFirst();
    }

    public PollResult poll(EventsProperties.Receiver receiver, Collection<UUID> acks, Map<UUID, String> errors,
                           int maxEvents) {
        // Queue first: an ack or error may name an event the receiver got by push before it was queued for polling
        delivery.enqueueNew(receiver);
        Timestamp now = Timestamp.from(clock.instant());
        transactions.executeWithoutResult(status -> {
            if (!acks.isEmpty()) {
                // One statement for all acknowledgements (up to 1000), only this receiver's rows
                jdbc.update(connection -> {
                    var statement = connection.prepareStatement("UPDATE identity.event_deliveries"
                            + " SET status = 'DELIVERED', finished_at = ?, last_error = NULL WHERE receiver_id = ?"
                            + " AND event_id = ANY(?) AND status IN ('PENDING', 'DEAD')");
                    statement.setTimestamp(1, now);
                    statement.setString(2, receiver.id());
                    statement.setArray(3, connection.createArrayOf("uuid", acks.toArray()));
                    return statement;
                });
            }
            errors.forEach((eventId, error) -> jdbc.update("UPDATE identity.event_deliveries SET status = 'REJECTED',"
                    + " finished_at = ?, last_error = ? WHERE receiver_id = ? AND event_id = ?"
                    + " AND status IN ('PENDING', 'DEAD')", now, truncate("receiver: " + error), receiver.id(), eventId));
        });
        // One extra row tells us whether more are waiting
        List<UUID> waiting = jdbc.queryForList("SELECT event_id FROM identity.event_deliveries"
                + " WHERE receiver_id = ? AND status IN ('PENDING', 'DEAD') ORDER BY seq LIMIT ?",
                UUID.class, receiver.id(), maxEvents + 1);
        Map<String, String> signed = new LinkedHashMap<>();
        for (UUID eventId : waiting.subList(0, Math.min(maxEvents, waiting.size()))) {
            diary.byId(eventId).ifPresent(event -> signed.put(eventId.toString(), sign(event, receiver)));
        }
        return new PollResult(signed, waiting.size() > maxEvents);
    }

    private String sign(StoredIdentityEvent line, EventsProperties.Receiver receiver) {
        return sets.issue(SetOf.event(line), receiver.audience());
    }

    private static String truncate(String text) {
        return text.length() <= MAX_ERROR_LENGTH ? text : text.substring(0, MAX_ERROR_LENGTH);
    }

    /** RFC 8936 response: jti to SET, and whether more are waiting. */
    public record PollResult(Map<String, String> sets, boolean moreAvailable) {
    }
}
