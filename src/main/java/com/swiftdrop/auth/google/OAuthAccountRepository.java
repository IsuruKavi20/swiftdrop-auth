package com.swiftdrop.auth.google;

import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

interface OAuthAccountRepository extends JpaRepository<OAuthAccount, UUID> {

    Optional<OAuthAccount> findByProviderAndProviderUserId(String provider, String providerUserId);

    List<OAuthAccount> findByUserId(UUID userId);

    @Modifying
    @Query("delete from OAuthAccount a where a.userId = :userId")
    int deleteByUserId(@Param("userId") UUID userId);

    boolean existsByUserIdAndProvider(UUID userId, String provider);
}
