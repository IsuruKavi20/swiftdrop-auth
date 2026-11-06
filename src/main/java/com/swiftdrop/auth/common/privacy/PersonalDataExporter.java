package com.swiftdrop.auth.common.privacy;

import java.util.UUID;

/**
 * Implemented by every module that stores personal data: it returns its own section of one person's data for the
 * "download my data" export. Modules never read each other's tables; a new module with personal data only adds one
 * implementation. Rule: data about the person, never secrets (no password or token hashes, no client secrets).
 */
public interface PersonalDataExporter {

    /** The section name in the export, snake_case, e.g. "linked_logins". */
    String section();

    /** This person's data in this module (maps, lists, plain values), or null/empty when there is none. */
    Object export(UUID userId);
}
