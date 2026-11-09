package com.swiftdrop.auth.admin.api;

import com.swiftdrop.auth.admin.AdminUsers;
import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.security.RequirePermission;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** Identity step 9b: everyone holding ADMIN, DISPATCHER or MERCHANT, for the periodic access review. */
@RestController
public class AccessReviewController {

    private final AdminUsers adminUsers;

    AccessReviewController(AdminUsers adminUsers) {
        this.adminUsers = adminUsers;
    }

    @GetMapping(ApiPaths.V1 + "/admin/access-review")
    @RequirePermission("user:read")
    public List<AdminUsers.RoleHolder> accessReview() {
        return adminUsers.accessReview();
    }
}
