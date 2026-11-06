package com.swiftdrop.auth.directory.api.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.UUID;

/** Body of POST /directory/users/lookup: at most 100 user ids per call. */
public record LookupBody(@NotNull @Size(max = 100) List<@NotNull UUID> ids) {
}
