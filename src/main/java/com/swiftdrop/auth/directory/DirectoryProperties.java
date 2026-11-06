package com.swiftdrop.auth.directory;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * {@code swiftdrop.directory.clients}: our own backends allowed to use the Directory API (client credentials). Only
 * the SHA-256 of each secret is configured. A bad entry stops the start: a typo must never widen access.
 */
@ConfigurationProperties("swiftdrop.directory")
public record DirectoryProperties(List<Client> clients) {

    public static final String READ = "directory:read";
    public static final String READ_EMAIL = "directory:read-email";

    public DirectoryProperties {
        clients = clients == null ? List.of() : List.copyOf(clients);
        if (clients.stream().map(Client::clientId).distinct().count() != clients.size()) {
            throw new IllegalArgumentException("swiftdrop.directory.clients: duplicate client-id");
        }
    }

    public record Client(String clientId, String secretSha256, List<String> permissions) {

        private static final Pattern CLIENT_ID = Pattern.compile("^svc_[a-z0-9-]{3,40}$");
        private static final Pattern SHA256_HEX = Pattern.compile("^[0-9a-f]{64}$");
        private static final Set<String> KNOWN = Set.of(READ, READ_EMAIL);

        public Client {
            if (clientId == null || !CLIENT_ID.matcher(clientId).matches()) {
                throw new IllegalArgumentException("directory client-id must look like svc_name");
            }
            if (secretSha256 == null || !SHA256_HEX.matcher(secretSha256).matches()) {
                throw new IllegalArgumentException("directory secret-sha256 must be 64 lowercase hex characters");
            }
            permissions = permissions == null ? List.of() : List.copyOf(permissions);
            if (!KNOWN.containsAll(permissions) || !permissions.contains(READ)) {
                throw new IllegalArgumentException("directory permissions: directory:read [+ directory:read-email]");
            }
        }

        /** Never print the secret hash. */
        @Override
        public String toString() {
            return "Client[" + clientId + ", permissions=" + permissions + "]";
        }
    }
}
