package com.swiftdrop.auth.user;

import org.springframework.data.jpa.repository.EntityGraph;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Short> {

    Optional<Role> findByName(RoleName name);

    /**
     * Locks the role row (SELECT ... FOR UPDATE) until the transaction ends. Used to serialise
     * "is this the last admin?" checks, so two admins cannot remove each other at the same moment.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT r FROM Role r WHERE r.name = :name")
    Optional<Role> lockByName(@Param("name") RoleName name);

    /** Roles together with their permissions, in one query. */
    @EntityGraph(attributePaths = "permissions")
    List<Role> findByNameIn(Collection<RoleName> names);
}
