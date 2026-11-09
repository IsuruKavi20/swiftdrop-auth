package com.swiftdrop.auth.audit;

/**
 * The result of checking the chain. {@code firstBrokenSeq} is the first row whose hash or link does not match
 * (changed, removed or inserted rows); {@code lastSeq}/{@code lastHash} are what the nightly anchor stores outside.
 */
public record AuditVerification(boolean ok, long rowsChecked, Long firstBrokenSeq, long lastSeq, String lastHash) {
}
