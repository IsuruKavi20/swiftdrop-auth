package com.swiftdrop.auth.user;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Read queries for the Directory API (identity step 5), kept in the module that owns the users table. Offset
 * paging as SCIM uses it (startIndex/count), ordered by creation time then id so pages never overlap.
 */
@Component
public class UserDirectoryQueries {

    private final EntityManager entityManager;

    UserDirectoryQueries(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Transactional(readOnly = true)
    public List<User> byIds(Collection<UUID> ids) {
        if (ids.isEmpty()) {
            return List.of();
        }
        return entityManager.createQuery("select distinct u from User u left join fetch u.roles where u.id in :ids",
                User.class).setParameter("ids", ids).getResultList();
    }

    /** @param role null = any role */
    @Transactional(readOnly = true)
    public List<User> page(RoleName role, UserStatus status, int offset, int limit) {
        TypedQuery<UUID> ids = entityManager.createQuery("select u.id from User u where u.status = :status"
                + roleFilter(role) + " order by u.createdAt, u.id", UUID.class).setParameter("status", status);
        if (role != null) {
            ids.setParameter("role", role);
        }
        List<UUID> pageIds = ids.setFirstResult(offset).setMaxResults(limit).getResultList();
        List<User> found = byIds(pageIds);
        // Keep the page's order (the fetch query doesn't)
        return pageIds.stream().flatMap(id -> found.stream().filter(user -> user.getId().equals(id))).toList();
    }

    @Transactional(readOnly = true)
    public long count(RoleName role, UserStatus status) {
        TypedQuery<Long> count = entityManager.createQuery("select count(u) from User u where u.status = :status"
                + roleFilter(role), Long.class).setParameter("status", status);
        if (role != null) {
            count.setParameter("role", role);
        }
        return count.getSingleResult();
    }

    private static String roleFilter(RoleName role) {
        return role == null ? "" : " and exists (select r from u.roles r where r.name = :role)";
    }
}
