package com.swiftdrop.auth.merchant;

import com.swiftdrop.auth.common.crypto.OpaqueTokens;
import com.swiftdrop.auth.common.error.ErrorCode;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.IssuedToken;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.RolePermissions;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * API credentials for merchants' software (OAuth 2.0 client credentials, RFC 6749 4.4): create (secret shown
 * once), list, revoke, and the token exchange itself. At most two active clients: enough to rotate a secret
 * (create the new one, switch, revoke the old one) without downtime.
 */
@Service
public class MerchantClients {

    static final int MAX_ACTIVE_CLIENTS = 2;
    private static final int CLIENT_ID_BYTES = 16;
    private static final String CLIENT_ID_PREFIX = "mc_";
    private static final Logger log = LoggerFactory.getLogger(MerchantClients.class);
    // Checked when a client id is unknown, so "unknown id" costs the same work as "wrong secret"
    private static final String DUMMY_HASH = OpaqueTokens.hash(OpaqueTokens.newToken());

    private final MerchantClientRepository clients;
    private final MerchantRepository merchants;
    private final UserRepository users;
    private final RolePermissions rolePermissions;
    private final AccessTokenIssuer tokens;
    private final Clock clock;

    MerchantClients(MerchantClientRepository clients, MerchantRepository merchants, UserRepository users,
                    RolePermissions rolePermissions, AccessTokenIssuer tokens, Clock clock) {
        this.clients = clients;
        this.merchants = merchants;
        this.users = users;
        this.rolePermissions = rolePermissions;
        this.tokens = tokens;
        this.clock = clock;
    }

    /** The only moment the secret exists outside the merchant's systems. */
    public record CreatedClient(String clientId, String clientSecret, String name, Instant createdAt) {

        @Override
        public String toString() {
            return "CreatedClient[clientId=" + clientId + ", clientSecret=redacted]";
        }
    }

    @Transactional
    public CreatedClient create(UUID ownerId, String name) {
        Merchant merchant = approvedMerchantLocked(ownerId);
        if (clients.countByMerchantIdAndRevokedAtIsNull(merchant.getId()) >= MAX_ACTIVE_CLIENTS) {
            throw new MerchantException(ErrorCode.MERCHANT_CLIENT_LIMIT);
        }
        String clientId = CLIENT_ID_PREFIX + OpaqueTokens.randomBase64Url(CLIENT_ID_BYTES);
        String secret = OpaqueTokens.newToken();
        Instant now = clock.instant();
        clients.save(new MerchantClient(merchant.getId(), clientId, OpaqueTokens.hash(secret), name, now));
        log.info("Merchant client created: merchant={} client={}", merchant.getId(), clientId);
        return new CreatedClient(clientId, secret, name, now);
    }

    /** A client as shown later: never the secret. */
    public record ClientView(String clientId, String name, Instant createdAt, Instant lastUsedAt) {
    }

    @Transactional(readOnly = true)
    public List<ClientView> list(UUID ownerId) {
        Merchant merchant = merchants.findByUserId(ownerId)
                .orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_NOT_FOUND));
        return clients.findByMerchantIdAndRevokedAtIsNullOrderByCreatedAtAsc(merchant.getId()).stream()
                .map(c -> new ClientView(c.getClientId(), c.getName(), c.getCreatedAt(), c.getLastUsedAt()))
                .toList();
    }

    /** Only the merchant's own clients: someone else's client id answers "not found" (no IDOR, no probing). */
    @Transactional
    public void revoke(UUID ownerId, String clientId) {
        Optional<Merchant> merchant = merchants.findByUserId(ownerId);
        MerchantClient client = clients.findByClientId(clientId)
                .filter(found -> merchant.isPresent() && found.getMerchantId().equals(merchant.get().getId()))
                .filter(MerchantClient::isActive)
                .orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_CLIENT_NOT_FOUND));
        client.revoke(clock.instant());
        log.info("Merchant client revoked: merchant={} client={}", client.getMerchantId(), clientId);
    }

    /**
     * Client credentials grant: a valid, active client of an APPROVED merchant whose account can still log in
     * gets a 15-minute token. Every failure is the same {@link InvalidClientException}.
     */
    @Transactional
    public IssuedToken issueToken(String clientId, String clientSecret) {
        Optional<MerchantClient> found = clients.findByClientId(clientId);
        boolean secretOk = OpaqueTokens.matches(found.map(MerchantClient::getSecretHash).orElse(DUMMY_HASH),
                OpaqueTokens.hash(clientSecret));
        if (found.isEmpty() || !secretOk || !found.get().isActive()) {
            throw new InvalidClientException();
        }
        MerchantClient client = found.get();
        Instant now = clock.instant();
        Merchant merchant = merchants.findById(client.getMerchantId())
                .filter(m -> m.getStatus() == MerchantStatus.APPROVED)
                .orElseThrow(InvalidClientException::new);
        User owner = users.findById(merchant.getUserId())
                .filter(user -> user.isUsable() && user.hasRole(RoleName.MERCHANT))
                .orElseThrow(InvalidClientException::new);
        client.markUsed(now);
        List<String> entitlements = rolePermissions.permissionsOf(List.of(RoleName.MERCHANT));
        return tokens.issueForMerchantClient(clientId, merchant.getId(), owner.getId(), List.of(RoleName.MERCHANT.name()),
                entitlements);
    }

    /**
     * Identity step 10 (introspection): is a machine token of this client still backed by an active client of an
     * APPROVED merchant whose owner can still log in? The same checks as issuing it.
     */
    @Transactional(readOnly = true)
    public boolean isStillValid(String clientId, UUID merchantId) {
        return clients.findByClientId(clientId).filter(MerchantClient::isActive)
                .filter(client -> client.getMerchantId().equals(merchantId))
                .flatMap(client -> merchants.findById(merchantId))
                .filter(merchant -> merchant.getStatus() == MerchantStatus.APPROVED)
                .flatMap(merchant -> users.findById(merchant.getUserId()))
                .filter(owner -> owner.isUsable() && owner.hasRole(RoleName.MERCHANT))
                .isPresent();
    }

    private Merchant approvedMerchantLocked(UUID ownerId) {
        User owner = users.lockById(ownerId).orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_NOT_FOUND));
        Merchant merchant = merchants.lockByUserId(ownerId)
                .orElseThrow(() -> new MerchantException(ErrorCode.MERCHANT_NOT_FOUND));
        if (merchant.getStatus() != MerchantStatus.APPROVED || !owner.hasRole(RoleName.MERCHANT)) {
            throw new MerchantException(ErrorCode.MERCHANT_NOT_APPROVED);
        }
        return merchant;
    }
}
