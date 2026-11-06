package com.swiftdrop.auth.signals;

import com.swiftdrop.auth.token.SecurityEventTokenIssuer;
import com.swiftdrop.auth.user.IdentityEventLog;
import com.swiftdrop.auth.user.StoredIdentityEvent;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Pushes identity events to the configured receivers (RFC 8935; identity step 6c).
 * <ol>
 *   <li><b>Queue:</b> each new diary line becomes one delivery row per receiver. Lines are committed in number order
 *       (see {@code IdentityEvents}), so the "queued up to" bookmark can never jump past a line still being written.
 *       A receiver starts with lines written after it was first configured.</li>
 *   <li><b>Lease:</b> a few due rows are claimed with {@code FOR UPDATE SKIP LOCKED} and pushed {@link #LEASE} into
 *       the future, then committed: another pod skips them, and no transaction is open during the HTTP call. A batch
 *       always finishes well inside its lease, and results are saved only while the lease is still ours.</li>
 *   <li><b>Send:</b> the event as a signed SET. 2xx = delivered; 400 = the receiver rejects it: REJECTED (final);
 *       anything else, including a line that can't be turned into a SET = retry after 2, 4, 8 ... s (max 10 min);
 *       after 24 h: DEAD (no more pushing, still collectable by polling).</li>
 * </ol>
 */
@Component
public class EventDelivery {

    private static final int QUEUE_BATCH = 500;
    // 4 sends x (3 s connect + 10 s read) = 52 s, well inside the 120 s lease: no row can be claimed twice
    private static final int SEND_BATCH = 4;
    private static final Duration LEASE = Duration.ofSeconds(120);
    private static final Duration MAX_BACKOFF = Duration.ofMinutes(10);
    private static final Duration GIVE_UP_AFTER = Duration.ofHours(24);
    private static final int MAX_ERROR_LENGTH = 200;
    private static final MediaType SECEVENT_JWT = MediaType.parseMediaType("application/secevent+jwt");
    private static final Logger log = LoggerFactory.getLogger(EventDelivery.class);

    private final EventsProperties settings;
    private final IdentityEventLog diary;
    private final SecurityEventTokenIssuer sets;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final HttpClient client;
    private final RestClient http;
    private final Clock clock;

    EventDelivery(EventsProperties settings, IdentityEventLog diary, SecurityEventTokenIssuer sets, JdbcTemplate jdbc,
                  TransactionTemplate transactions, Clock clock) {
        this.settings = settings;
        this.diary = diary;
        this.sets = sets;
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.clock = clock;
        // Short timeouts, no redirects: a slow or redirecting receiver can't hold our sender or send SETs elsewhere
        this.client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        JdkClientHttpRequestFactory requests = new JdkClientHttpRequestFactory(client);
        requests.setReadTimeout(Duration.ofSeconds(10));
        this.http = RestClient.builder().requestFactory(requests).build();
    }

    @PreDestroy
    void closeHttpClient() {
        client.close();
    }

    /** A newly configured receiver starts at the current end of the diary. */
    @EventListener(ApplicationReadyEvent.class)
    void registerReceivers() {
        settings.receivers().forEach(this::ensureRegistered);
    }

    @Scheduled(fixedDelayString = "${swiftdrop.events.push-interval:2s}")
    void onSchedule() {
        if (settings.pushEnabled() && !settings.receivers().isEmpty()) {
            deliverDue();
        }
    }

    /** One round: queue new events, then send what is due. Safe to run on several pods at once. */
    public void deliverDue() {
        for (EventsProperties.Receiver receiver : settings.receivers()) {
            try {
                enqueueNew(receiver);
                for (Claimed claimed : claimDue(receiver)) {
                    sendSafely(receiver, claimed);
                }
            } catch (RuntimeException unexpected) {
                // One receiver's trouble never stops the others; the next round retries
                log.error("Identity event delivery round failed for receiver={}", receiver.id(), unexpected);
            }
        }
    }

    /** Also used by polling, so a polling-only receiver sees the newest events. */
    void enqueueNew(EventsProperties.Receiver receiver) {
        ensureRegistered(receiver);   // the timer may fire before the startup registration ran
        boolean more = true;
        while (more) {
            more = Boolean.TRUE.equals(transactions.execute(status -> {
                // Row lock: two pods queue one after the other, never the same lines twice
                Long cursor = jdbc.queryForObject("SELECT enqueued_up_to FROM identity.event_receivers"
                        + " WHERE receiver_id = ? FOR UPDATE", Long.class, receiver.id());
                List<StoredIdentityEvent> fresh = diary.after(cursor, QUEUE_BATCH);
                Timestamp now = Timestamp.from(clock.instant());
                for (StoredIdentityEvent event : fresh) {
                    jdbc.update("INSERT INTO identity.event_deliveries (event_id, receiver_id, seq, next_attempt_at,"
                            + " created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                            event.id(), receiver.id(), event.seq(), now, now);
                }
                if (!fresh.isEmpty()) {
                    jdbc.update("UPDATE identity.event_receivers SET enqueued_up_to = ? WHERE receiver_id = ?",
                            fresh.getLast().seq(), receiver.id());
                }
                return fresh.size() == QUEUE_BATCH;
            }));
        }
    }

    private void ensureRegistered(EventsProperties.Receiver receiver) {
        jdbc.update("INSERT INTO identity.event_receivers (receiver_id, enqueued_up_to) VALUES (?, ?)"
                + " ON CONFLICT (receiver_id) DO NOTHING", receiver.id(), diary.latestSeq());
    }

    // One atomic statement (auto-commit): lock the due rows, skip rows another pod holds, push their next attempt
    // past the lease so nobody else picks them up while we send. Microseconds: what Postgres stores, so the lease
    // value we compare against later is exactly the stored one.
    private List<Claimed> claimDue(EventsProperties.Receiver receiver) {
        Instant now = clock.instant();
        Instant lease = now.plus(LEASE).truncatedTo(ChronoUnit.MICROS);
        return jdbc.query("UPDATE identity.event_deliveries d SET next_attempt_at = ?"
                        + " WHERE (d.event_id, d.receiver_id) IN ("
                        + "   SELECT event_id, receiver_id FROM identity.event_deliveries"
                        + "   WHERE receiver_id = ? AND status = 'PENDING' AND next_attempt_at <= ?"
                        + "   ORDER BY seq LIMIT ? FOR UPDATE SKIP LOCKED)"
                        + " RETURNING d.event_id, d.attempts, d.created_at",
                (rs, n) -> new Claimed(rs.getObject("event_id", UUID.class), rs.getInt("attempts"),
                        rs.getTimestamp("created_at").toInstant(), lease),
                Timestamp.from(lease), receiver.id(), Timestamp.from(now), SEND_BATCH);
    }

    // A line that can't be signed or sent must never stop the rest of the batch
    private void sendSafely(EventsProperties.Receiver receiver, Claimed claimed) {
        try {
            send(receiver, claimed);
        } catch (RuntimeException broken) {
            retryOrGiveUp(receiver, claimed, broken.getClass().getSimpleName());
        }
    }

    private void send(EventsProperties.Receiver receiver, Claimed claimed) {
        Optional<StoredIdentityEvent> event = diary.byId(claimed.eventId());
        if (event.isEmpty()) {
            finish(receiver, claimed, "DEAD", "event missing");
            return;
        }
        String set = sets.issue(SetOf.event(event.get()), receiver.audience());
        int status;
        try {
            status = http.post().uri(receiver.pushUrl()).contentType(SECEVENT_JWT)
                    .accept(MediaType.APPLICATION_JSON).body(set)
                    .exchange((request, response) -> response.getStatusCode().value());
        } catch (RuntimeException unreachable) {
            retryOrGiveUp(receiver, claimed, unreachable.getClass().getSimpleName());
            return;
        }
        if (status >= 200 && status < 300) {
            finish(receiver, claimed, "DELIVERED", null);
        } else if (status == 400) {
            finish(receiver, claimed, "REJECTED", "rejected by receiver (400)");
            log.error("Identity event rejected by receiver: receiver={} event={}", receiver.id(), claimed.eventId());
        } else {
            retryOrGiveUp(receiver, claimed, "HTTP " + status);
        }
    }

    private void retryOrGiveUp(EventsProperties.Receiver receiver, Claimed claimed, String error) {
        Instant now = clock.instant();
        if (claimed.createdAt().plus(GIVE_UP_AFTER).isBefore(now)) {
            finish(receiver, claimed, "DEAD", "gave up after 24 h: " + error);
            log.error("Identity event delivery given up: receiver={} event={}", receiver.id(), claimed.eventId());
            return;
        }
        int attempt = claimed.attempts() + 1;
        Duration wait = Duration.ofSeconds(1L << Math.min(attempt, 20));
        Instant next = now.plus(wait.compareTo(MAX_BACKOFF) > 0 ? MAX_BACKOFF : wait);
        // Only while the lease is still ours: a late finisher never overwrites someone else's newer result
        jdbc.update("UPDATE identity.event_deliveries SET attempts = ?, next_attempt_at = ?, last_error = ?"
                        + " WHERE event_id = ? AND receiver_id = ? AND status = 'PENDING' AND next_attempt_at = ?",
                attempt, Timestamp.from(next), truncate(error), claimed.eventId(), receiver.id(),
                Timestamp.from(claimed.lease()));
        log.warn("Identity event delivery failed, will retry: receiver={} event={} attempt={} error={}",
                receiver.id(), claimed.eventId(), attempt, error);
    }

    private void finish(EventsProperties.Receiver receiver, Claimed claimed, String status, String error) {
        jdbc.update("UPDATE identity.event_deliveries SET status = ?, attempts = ?, finished_at = ?, last_error = ?"
                        + " WHERE event_id = ? AND receiver_id = ? AND status = 'PENDING' AND next_attempt_at = ?",
                status, claimed.attempts() + 1, Timestamp.from(clock.instant()), error == null ? null : truncate(error),
                claimed.eventId(), receiver.id(), Timestamp.from(claimed.lease()));
    }

    private static String truncate(String text) {
        return text.length() <= MAX_ERROR_LENGTH ? text : text.substring(0, MAX_ERROR_LENGTH);
    }

    private record Claimed(UUID eventId, int attempts, Instant createdAt, Instant lease) {
    }
}
