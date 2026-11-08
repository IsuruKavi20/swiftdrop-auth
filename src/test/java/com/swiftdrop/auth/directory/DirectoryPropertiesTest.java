package com.swiftdrop.auth.directory;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** A bad service-client entry must stop the start: a typo must never widen access. */
class DirectoryPropertiesTest {

    private static final String HASH = "a".repeat(64);

    @Test
    void acceptsAWellFormedClient() {
        DirectoryProperties.Client client = new DirectoryProperties.Client("svc_swiftdrop", HASH,
                List.of("directory:read", "directory:read-email"));

        assertThat(client.toString()).doesNotContain(HASH);   // never print the secret hash
    }

    @Test
    void refusesBadClientIds() {
        assertThatThrownBy(() -> new DirectoryProperties.Client("mc_lookslikeamerchant", HASH,
                List.of("directory:read"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DirectoryProperties.Client("svc_Upper", HASH, List.of("directory:read")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesAPlainSecretInsteadOfItsHash() {
        assertThatThrownBy(() -> new DirectoryProperties.Client("svc_swiftdrop", "my-plain-secret",
                List.of("directory:read"))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesUnknownPermissionsAndEmailWithoutRead() {
        assertThatThrownBy(() -> new DirectoryProperties.Client("svc_swiftdrop", HASH, List.of("user:manage-roles")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DirectoryProperties.Client("svc_swiftdrop", HASH,
                List.of("directory:read-email"))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anEventsOnlyClientNeedsNoDirectoryPermission() {
        assertThat(new DirectoryProperties.Client("svc_swiftdrop-backend", HASH, List.of("events:read"))
                .permissions()).containsExactly("events:read");
        assertThatThrownBy(() -> new DirectoryProperties.Client("svc_swiftdrop", HASH, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesDuplicateClientIds() {
        DirectoryProperties.Client client = new DirectoryProperties.Client("svc_swiftdrop", HASH,
                List.of("directory:read"));

        assertThatThrownBy(() -> new DirectoryProperties(List.of(client, client)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
