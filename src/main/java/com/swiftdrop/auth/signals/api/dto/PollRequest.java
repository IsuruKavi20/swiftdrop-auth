package com.swiftdrop.auth.signals.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/** RFC 8936 poll request. All fields optional; long polling is not offered (we always answer at once). */
public record PollRequest(
        @Size(max = 1000) List<UUID> ack,
        @Size(max = 1000) Map<String, @Valid SetError> setErrs,
        @Min(0) @Max(100) Integer maxEvents,
        @JsonProperty("returnImmediately") Boolean returnImmediately) {

    /** RFC 8936 2.4 / RFC 8935 2.3 error for one SET. */
    public record SetError(@Size(max = 100) String err, @Size(max = 200) String description) {
    }
}
