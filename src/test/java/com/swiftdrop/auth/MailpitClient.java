package com.swiftdrop.auth;

import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;

import java.time.Duration;
import java.util.Optional;

/** Reads the fake inbox of the Mailpit test container through its REST API. */
public class MailpitClient {

    private static final Duration WAIT_FOR_MAIL = Duration.ofSeconds(15);
    private static final Duration POLL_EVERY = Duration.ofMillis(200);

    private final RestClient api;

    MailpitClient(String baseUrl) {
        this.api = RestClient.builder().baseUrl(baseUrl).build();
    }

    public record Mail(String subject, String text) {
    }

    /** Waits (emails are sent asynchronously, after commit) for the newest message to the given address. */
    public Mail awaitMessageTo(String address, String subject) {
        long deadline = System.nanoTime() + WAIT_FOR_MAIL.toNanos();
        while (System.nanoTime() < deadline) {
            Optional<Mail> mail = findMessage(address, subject);
            if (mail.isPresent()) {
                return mail.get();
            }
            sleep();
        }
        throw new AssertionError("No email '" + subject + "' to " + address + " within " + WAIT_FOR_MAIL);
    }

    public int countMessagesTo(String address) {
        JsonNode found = api.get().uri("/api/v1/search?query={q}", "to:\"" + address + "\"")
                .retrieve().body(JsonNode.class);
        return found == null ? 0 : found.path("messages_count").asInt();
    }

    private Optional<Mail> findMessage(String address, String subject) {
        JsonNode found = api.get().uri("/api/v1/search?query={q}", "to:\"" + address + "\"")
                .retrieve().body(JsonNode.class);
        if (found == null) {
            return Optional.empty();
        }
        for (JsonNode message : found.path("messages")) {
            if (subject.equals(message.path("Subject").asString())) {
                JsonNode full = api.get().uri("/api/v1/message/{id}", message.path("ID").asString())
                        .retrieve().body(JsonNode.class);
                return Optional.of(new Mail(subject, full == null ? "" : full.path("Text").asString()));
            }
        }
        return Optional.empty();
    }

    private static void sleep() {
        try {
            Thread.sleep(POLL_EVERY);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
