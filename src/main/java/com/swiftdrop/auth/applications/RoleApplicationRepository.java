package com.swiftdrop.auth.applications;

import com.swiftdrop.auth.user.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

interface RoleApplicationRepository extends JpaRepository<RoleApplication, UUID> {

    boolean existsByUserIdAndRoleAndStatus(UUID userId, RoleName role, ApplicationStatus status);

    boolean existsByUserIdAndRoleAndStatusAndDecidedAtAfter(UUID userId, RoleName role, ApplicationStatus status,
                                                            Instant after);

    List<RoleApplication> findByUserIdOrderByCreatedAtDesc(UUID userId);

    Optional<RoleApplication> findByIdAndUserId(UUID id, UUID userId);
}
