package com.swiftdrop.auth.merchant.api;

import com.swiftdrop.auth.common.web.ApiPaths;
import com.swiftdrop.auth.merchant.MerchantApplications;
import com.swiftdrop.auth.merchant.MerchantStatus;
import com.swiftdrop.auth.merchant.api.dto.MerchantApplicationResponse;
import com.swiftdrop.auth.merchant.api.dto.MerchantDecisionRequest;
import com.swiftdrop.auth.merchant.api.dto.MerchantStatusRequest;
import com.swiftdrop.auth.security.RequirePermission;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** The admin approval step: list applications by status, approve or reject one. */
@RestController
@RequestMapping(ApiPaths.V1 + "/admin/merchants")
public class AdminMerchantController {

    private final MerchantApplications applications;

    public AdminMerchantController(MerchantApplications applications) {
        this.applications = applications;
    }

    @GetMapping
    @RequirePermission("merchant:approve")
    public List<MerchantApplicationResponse> list(@RequestParam(defaultValue = "PENDING") MerchantStatus status) {
        return applications.list(status).stream().map(MerchantApplicationResponse::from).toList();
    }

    @PostMapping("/{merchantId}/decision")
    @RequirePermission("merchant:approve")
    public MerchantApplicationResponse decide(@AuthenticationPrincipal Jwt admin, @PathVariable UUID merchantId,
                                              @Valid @RequestBody MerchantDecisionRequest request) {
        return MerchantApplicationResponse.from(applications.decide(MerchantController.userId(admin), merchantId,
                request.decision(), request.reason()));
    }

    @PostMapping("/{merchantId}/status")
    @RequirePermission("merchant:approve")
    public MerchantApplicationResponse changeStatus(@AuthenticationPrincipal Jwt admin, @PathVariable UUID merchantId,
                                                    @Valid @RequestBody MerchantStatusRequest request) {
        return MerchantApplicationResponse.from(applications.changeStatus(MerchantController.userId(admin), merchantId,
                request.change()));
    }
}
