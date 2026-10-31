package com.swiftdrop.auth.user.api.dto;

import java.util.List;
import java.util.UUID;

/** Who the presented access token says you are. */
public record MeResponse(UUID userId, List<String> roles) {
}
