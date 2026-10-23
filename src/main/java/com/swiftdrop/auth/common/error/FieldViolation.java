package com.swiftdrop.auth.common.error;

/** One invalid field: its name and the rule it broke (e.g. "Size"). Never the rejected value. */
public record FieldViolation(String field, String rule) {
}
