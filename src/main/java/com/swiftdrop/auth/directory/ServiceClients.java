package com.swiftdrop.auth.directory;

import com.swiftdrop.auth.common.crypto.OpaqueTokens;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.IssuedToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Client credentials for our own backends (svc_...): a 15-minute token carrying only their directory permissions. */
@Component
public class ServiceClients {

    public static final String PREFIX = "svc_";
    private static final String SERVICE_ROLE = "SERVICE";
    // Compared against when the client is unknown, so timing doesn't reveal which client ids exist
    private static final String DUMMY_HASH = OpaqueTokens.hash("no-such-service-client");
    private static final Logger log = LoggerFactory.getLogger(ServiceClients.class);

    private final Map<String, DirectoryProperties.Client> clients;
    private final AccessTokenIssuer tokens;

    ServiceClients(DirectoryProperties properties, AccessTokenIssuer tokens) {
        this.clients = properties.clients().stream()
                .collect(Collectors.toUnmodifiableMap(DirectoryProperties.Client::clientId, Function.identity()));
        this.tokens = tokens;
    }

    public static boolean isServiceClientId(String clientId) {
        return clientId != null && clientId.startsWith(PREFIX);
    }

    /** The client, if id and secret are right (same constant-time check as the token endpoint). */
    public Optional<DirectoryProperties.Client> authenticate(String clientId, String secret) {
        DirectoryProperties.Client client = clients.get(clientId);
        boolean secretOk = OpaqueTokens.matches(client == null ? DUMMY_HASH : client.secretSha256(),
                OpaqueTokens.hash(secret == null ? "" : secret));
        return client != null && secretOk ? Optional.of(client) : Optional.empty();
    }

    /** A service client's token stays good only while that client is still configured. */
    public boolean isConfigured(String clientId) {
        return clients.containsKey(clientId);
    }

    /** Empty for an unknown client or a wrong secret (the caller answers invalid_client either way). */
    public Optional<IssuedToken> issueToken(String clientId, String secret) {
        DirectoryProperties.Client client = clients.get(clientId);
        boolean secretOk = OpaqueTokens.matches(client == null ? DUMMY_HASH : client.secretSha256(),
                OpaqueTokens.hash(secret == null ? "" : secret));
        if (client == null || !secretOk) {
            return Optional.empty();
        }
        log.info("Service client token issued client={}", clientId);
        return Optional.of(tokens.issueForClient(clientId, null, List.of(SERVICE_ROLE), client.permissions()));
    }
}
