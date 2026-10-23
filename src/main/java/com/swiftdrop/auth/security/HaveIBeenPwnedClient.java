package com.swiftdrop.auth.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Have I Been Pwned "range" lookup with k-anonymity: only the first 5 hex characters of the
 * password's SHA-1 are sent; the rest is compared here. The whole lookup has a total deadline,
 * and any failure fails open (the password is allowed) with a log line that never contains the hash.
 */
public class HaveIBeenPwnedClient implements CompromisedPasswordChecker {

    private static final Logger log = LoggerFactory.getLogger(HaveIBeenPwnedClient.class);
    private static final int PREFIX_LENGTH = 5;
    private static final CompromisedPasswordDecision NOT_COMPROMISED = new CompromisedPasswordDecision(false);

    private final RestClient client;
    private final Duration deadline;
    private final ExecutorService lookups = Executors.newVirtualThreadPerTaskExecutor();

    public HaveIBeenPwnedClient(RestClient client, Duration deadline) {
        this.client = client;
        this.deadline = deadline;
    }

    @Override
    public CompromisedPasswordDecision check(String password) {
        if (password == null) {
            return NOT_COMPROMISED;
        }
        String hash = sha1Hex(password);
        String prefix = hash.substring(0, PREFIX_LENGTH);
        Future<String> response = lookups.submit(() -> client.get().uri("{prefix}", prefix).retrieve().body(String.class));
        try {
            String body = response.get(deadline.toMillis(), TimeUnit.MILLISECONDS);
            return new CompromisedPasswordDecision(containsSuffix(body, hash.substring(PREFIX_LENGTH)));
        } catch (TimeoutException e) {
            response.cancel(true);
            return failOpen(e);
        } catch (ExecutionException e) {
            return failOpen(e.getCause());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return failOpen(e);
        }
    }

    // Each line is "SUFFIX:COUNT". Padding rows (Add-Padding) have count 0 and are not real breaches.
    private static boolean containsSuffix(String body, String suffix) {
        if (body == null) {
            return false;
        }
        return body.lines().anyMatch(line -> {
            int colon = line.indexOf(':');
            return colon > 0
                    && line.substring(0, colon).equalsIgnoreCase(suffix)
                    && !line.substring(colon + 1).trim().equals("0");
        });
    }

    // Only the failure type is logged: messages can contain the request URL, i.e. part of the password hash
    private static CompromisedPasswordDecision failOpen(Throwable failure) {
        log.warn("Breached-password check unavailable ({}); allowing the password",
                failure == null ? "unknown" : failure.getClass().getSimpleName());
        return NOT_COMPROMISED;
    }

    private static String sha1Hex(String password) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1").digest(password.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().withUpperCase().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 is required by the Java platform", e);
        }
    }
}
