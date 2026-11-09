package com.swiftdrop.auth.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;

/**
 * The hash of one row: SHA-256 over the previous row's hash and every field of this row. Each field is written as
 * "length:value|" (a missing one as "-|"), so no two different rows can produce the same input text.
 */
final class AuditChain {

    static final String GENESIS = "0".repeat(64);

    private AuditChain() {
    }

    record Row(long seq, Instant at, String actorType, String actorId, String action, String targetType,
               String targetId, String ip, String requestId, String details) {
    }

    static String hash(String prevHash, Row row) {
        StringBuilder text = new StringBuilder(256);
        for (String field : new String[] {prevHash, Long.toString(row.seq()), micros(row.at()), row.actorType(),
                row.actorId(), row.action(), row.targetType(), row.targetId(), row.ip(), row.requestId(),
                row.details()}) {
            text.append(field == null ? "-" : field.length() + ":" + field).append('|');
        }
        return HexFormat.of().formatHex(sha256(text.toString()));
    }

    /** Postgres keeps microseconds: the hash uses exactly what is stored, so it can be recomputed later. */
    static Instant storable(Instant at) {
        return at.truncatedTo(ChronoUnit.MICROS);
    }

    private static String micros(Instant at) {
        return Long.toString(ChronoUnit.MICROS.between(Instant.EPOCH, at));
    }

    private static byte[] sha256(String text) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is always available", e);
        }
    }
}
