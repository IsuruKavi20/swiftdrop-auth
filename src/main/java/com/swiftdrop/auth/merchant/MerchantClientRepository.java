package com.swiftdrop.auth.merchant;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

interface MerchantClientRepository extends JpaRepository<MerchantClient, UUID> {

    Optional<MerchantClient> findByClientId(String clientId);

    List<MerchantClient> findByMerchantIdAndRevokedAtIsNullOrderByCreatedAtAsc(UUID merchantId);

    long countByMerchantIdAndRevokedAtIsNull(UUID merchantId);
}
