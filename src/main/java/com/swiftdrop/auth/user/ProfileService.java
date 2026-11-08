package com.swiftdrop.auth.user;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

/**
 * The logged-in user's own identity profile (identity step 3a). Edits are safe against lost updates: the caller
 * sends the ETag it read; if the profile changed since, the edit is refused (412) instead of overwriting.
 */
@Service
public class ProfileService {

    private static final int ETAG_BYTES = 16;
    // Cannot occur inside any profile value (control characters are rejected), so fields can't run together
    private static final String SEPARATOR = String.valueOf((char) 0);

    private final UserRepository users;
    private final PicturePolicy pictures;
    private final IdentityEvents events;
    private final Clock clock;

    ProfileService(UserRepository users, PicturePolicy pictures, IdentityEvents events, Clock clock) {
        this.users = users;
        this.pictures = pictures;
        this.events = events;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public ProfileView get(UUID userId) {
        return view(users.findById(userId).filter(User::isUsable).orElseThrow(ProfileService::noSuchUser));
    }

    /** @param ifMatch the ETag the client read; required (the controller answers 428 without it) */
    @Transactional
    public ProfileView update(UUID userId, String ifMatch, ProfilePatch patch) {
        // Locked: a second edit at the same moment waits, then sees the new ETag and gets 412
        User user = users.lockById(userId).filter(User::isUsable).orElseThrow(ProfileService::noSuchUser);
        if (!etagOf(user).equals(ifMatch)) {
            throw new ProfileChangedException();
        }
        IdentityProfile edited = IdentityProfile.ofUser(
                patch.touches("name") ? PersonName.of(patch.valueOf("name")) : stored(user.getName()),
                patch.touches("given_name") ? nameOrNull(patch.valueOf("given_name")) : stored(user.getGivenName()),
                patch.touches("family_name") ? nameOrNull(patch.valueOf("family_name")) : stored(user.getFamilyName()),
                patch.touches("picture")
                        ? pictures.requireTrusted(IdentityProfile.requireSafePictureUrl(patch.valueOf("picture")))
                        : user.getPictureUrl(),
                patch.touches("locale") ? IdentityProfile.requireLanguageTag(patch.valueOf("locale")) : user.getLocale());
        if (user.setOwnProfile(edited, clock.instant())) {
            events.profileUpdated(user);
        }
        return view(user);
    }

    private static PersonName nameOrNull(String raw) {
        return raw == null ? null : PersonName.of(raw);
    }

    // Stored values passed validation when written; an unexpected one is dropped rather than blocking the edit
    private static PersonName stored(String value) {
        return value == null ? null : PersonName.ofOptional(value).orElse(null);
    }

    private static ProfileView view(User user) {
        return new ProfileView(user.getId(), user.getName(), user.getGivenName(), user.getFamilyName(),
                user.getPictureUrl(), user.getLocale(), user.getEmail(), user.isEmailVerified(),
                user.getProfileUpdatedAt(), etagOf(user));
    }

    // A fingerprint of exactly what the client sees. Not the row version: that also moves on every login, which
    // would make an edit fail after a login for no visible reason.
    static String etagOf(User user) {
        String visible = String.join(SEPARATOR, Objects.toString(user.getName(), ""),
                Objects.toString(user.getGivenName(), ""), Objects.toString(user.getFamilyName(), ""),
                Objects.toString(user.getPictureUrl(), ""), Objects.toString(user.getLocale(), ""),
                user.getEmail(), Boolean.toString(user.isEmailVerified()));
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(visible.getBytes(StandardCharsets.UTF_8));
            return "\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOf(hash, ETAG_BYTES))
                    + "\"";
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is required by every Java runtime", impossible);
        }
    }

    // A valid token for a user that no longer exists or is no longer active (deleted, disabled): treated like an
    // invalid token (401). Otherwise a deleted account could write personal data back onto its tombstone.
    private static BadCredentialsException noSuchUser() {
        return new BadCredentialsException("Token user does not exist");
    }
}
