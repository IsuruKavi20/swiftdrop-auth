package com.swiftdrop.auth.directory;

import com.swiftdrop.auth.common.error.ErrorCode;
import com.swiftdrop.auth.common.privacy.ExportMap;
import com.swiftdrop.auth.user.RoleName;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserDirectoryQueries;
import com.swiftdrop.auth.user.UserStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The Directory API (identity step 5; design doc Tool D): who a person is, for SwiftDrop's backend. SCIM 2.0 shapes
 * (active, meta.lastModified, startIndex/count/totalResults/Resources). Email only with directory:read-email, and
 * every email read is logged (who read how many; never the addresses). A deleted person shows only that they're gone.
 */
@Service
public class DirectoryService {

    public static final int MAX_PAGE = 100;
    // Offset paging: a huge offset still makes the database walk past every skipped row
    private static final int MAX_START_INDEX = 10_000;
    private static final int DEFAULT_PAGE = 50;
    private static final Logger log = LoggerFactory.getLogger(DirectoryService.class);

    private final UserDirectoryQueries queries;

    DirectoryService(UserDirectoryQueries queries) {
        this.queries = queries;
    }

    public Map<String, Object> get(UUID id, boolean withEmail, String client) {
        User user = queries.byIds(List.of(id)).stream().findFirst()
                .orElseThrow(() -> new DirectoryException(ErrorCode.USER_NOT_FOUND));
        logEmailRead(withEmail, client, 1);
        return entry(user, withEmail);
    }

    public Map<String, Object> lookup(Collection<UUID> ids, boolean withEmail, String client) {
        List<Map<String, Object>> found = queries.byIds(ids).stream().map(user -> entry(user, withEmail)).toList();
        logEmailRead(withEmail, client, found.size());
        return listResponse(found.size(), 1, found);
    }

    public Map<String, Object> list(String role, String status, Integer startIndex, Integer count, boolean withEmail,
                                    String client) {
        RoleName roleFilter = role == null ? null : parse(RoleName.class, role);
        UserStatus statusFilter = status == null ? UserStatus.ACTIVE : parse(UserStatus.class, status);
        if (statusFilter == UserStatus.DELETED) {
            throw new DirectoryException(ErrorCode.VALIDATION_FAILED);   // living accounts only; erased people stay erased
        }
        int start = startIndex == null ? 1 : startIndex;
        int size = count == null ? DEFAULT_PAGE : count;
        if (start < 1 || start > MAX_START_INDEX || size < 1 || size > MAX_PAGE) {
            throw new DirectoryException(ErrorCode.VALIDATION_FAILED);
        }
        List<Map<String, Object>> page = queries.page(roleFilter, statusFilter, start - 1, size).stream()
                .map(user -> entry(user, withEmail)).toList();
        logEmailRead(withEmail, client, page.size());
        return listResponse(queries.count(roleFilter, statusFilter), start, page);
    }

    private static Map<String, Object> entry(User user, boolean withEmail) {
        boolean deleted = user.getStatus() == UserStatus.DELETED;
        ExportMap entry = ExportMap.of()
                .put("id", user.getId())
                .put("active", user.isUsable())
                .put("status", user.getStatus())
                .put("name", deleted ? null : user.getName())
                .put("picture", deleted ? null : user.getPictureUrl())
                .put("roles", deleted ? List.of() : user.roleNames());
        if (withEmail && !deleted) {
            entry.put("email", user.getEmail()).put("email_verified", user.isEmailVerified());
        }
        Map<String, Object> result = entry.build();
        result.values().removeIf(value -> value == null);
        result.put("meta", Map.of("lastModified",
                user.getProfileUpdatedAt() != null ? user.getProfileUpdatedAt() : user.getUpdatedAt()));
        return result;
    }

    private static Map<String, Object> listResponse(long total, int start, List<Map<String, Object>> resources) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("totalResults", total);
        response.put("startIndex", start);
        response.put("itemsPerPage", resources.size());
        response.put("Resources", resources);
        return response;
    }

    private static void logEmailRead(boolean withEmail, String client, int count) {
        if (withEmail && count > 0) {
            log.info("Directory email read client={} people={}", client, count);
        }
    }

    private static <E extends Enum<E>> E parse(Class<E> type, String value) {
        try {
            return Enum.valueOf(type, value);
        } catch (IllegalArgumentException unknown) {
            throw new DirectoryException(ErrorCode.VALIDATION_FAILED);
        }
    }
}
