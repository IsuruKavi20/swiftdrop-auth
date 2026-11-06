package com.swiftdrop.auth.user;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/** Who may write the identity profile: the user's own edits always win over a provider like Google. */
class UserProfileTest {

    private static final Instant T1 = Instant.parse("2026-11-06T10:00:00Z");
    private static final Instant T2 = Instant.parse("2026-11-06T11:00:00Z");

    private static final IdentityProfile GOOGLE = IdentityProfile.fromProvider("Isuru Kavinda", "Isuru", "Kavinda",
            "https://lh3.googleusercontent.com/a/photo", "si-LK");

    @Test
    void newAccountHasNoProfile() {
        User user = newUser();

        assertThat(user.getName()).isNull();
        assertThat(user.getProfileSource()).isNull();
        assertThat(user.getProfileUpdatedAt()).isNull();
    }

    @Test
    void ownProfileIsMarkedAsTheUsers() {
        User user = newUser();

        user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Nimal Perera")), T1);

        assertThat(user.getName()).isEqualTo("Nimal Perera");
        assertThat(user.getProfileSource()).isEqualTo(ProfileSource.USER);
        assertThat(user.getProfileUpdatedAt()).isEqualTo(T1);
    }

    @Test
    void providerFillsAnEmptyProfile() {
        User user = newUser();

        boolean changed = user.applyProviderProfile(GOOGLE, T1);

        assertThat(changed).isTrue();
        assertThat(user.getName()).isEqualTo("Isuru Kavinda");
        assertThat(user.getGivenName()).isEqualTo("Isuru");
        assertThat(user.getFamilyName()).isEqualTo("Kavinda");
        assertThat(user.getPictureUrl()).isEqualTo("https://lh3.googleusercontent.com/a/photo");
        assertThat(user.getLocale()).isEqualTo("si-LK");
        assertThat(user.getProfileSource()).isEqualTo(ProfileSource.GOOGLE);
        assertThat(user.getProfileUpdatedAt()).isEqualTo(T1);
    }

    @Test
    void providerKeepsAProviderProfileUpToDate() {
        User user = newUser();
        user.applyProviderProfile(GOOGLE, T1);

        user.applyProviderProfile(IdentityProfile.fromProvider("Isuru K. Premasiri", null, null,
                "https://lh3.googleusercontent.com/a/new", null), T2);

        assertThat(user.getName()).isEqualTo("Isuru K. Premasiri");
        assertThat(user.getPictureUrl()).isEqualTo("https://lh3.googleusercontent.com/a/new");
        assertThat(user.getGivenName()).as("missing claims don't erase what we have").isEqualTo("Isuru");
        assertThat(user.getProfileUpdatedAt()).isEqualTo(T2);
    }

    @Test
    void providerNeverOverwritesTheUsersOwnName() {
        User user = newUser();
        user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Nimal Perera")), T1);

        user.applyProviderProfile(GOOGLE, T2);

        assertThat(user.getName()).isEqualTo("Nimal Perera");
        assertThat(user.getProfileSource()).isEqualTo(ProfileSource.USER);
    }

    @Test
    void providerMayFillFieldsTheUserNeverSet() {
        User user = newUser();
        user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Nimal Perera")), T1);

        boolean changed = user.applyProviderProfile(GOOGLE, T2);

        assertThat(changed).isTrue();
        assertThat(user.getPictureUrl()).isEqualTo("https://lh3.googleusercontent.com/a/photo");
        assertThat(user.getLocale()).isEqualTo("si-LK");
        assertThat(user.getProfileUpdatedAt()).isEqualTo(T2);
    }

    @Test
    void providerDoesNotMixAnotherNamesPartsIntoTheUsersOwnName() {
        User user = newUser();
        user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Kasun Perera")), T1);

        user.applyProviderProfile(GOOGLE, T2);

        assertThat(user.getName()).isEqualTo("Kasun Perera");
        assertThat(user.getGivenName()).as("Google's given name belongs to Google's name").isNull();
        assertThat(user.getFamilyName()).isNull();
    }

    @Test
    void sameOwnProfileTwiceChangesNothing() {
        User user = newUser();
        user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Nimal Perera")), T1);

        boolean changed = user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Nimal Perera")), T2);

        assertThat(changed).isFalse();
        assertThat(user.getProfileUpdatedAt()).isEqualTo(T1);
    }

    @Test
    void clearingRemovesEveryProfileFieldAndItsOwner() {
        User user = newUser();
        user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Support: visit evil.example")), T1);

        user.clearProfile(T2);

        assertThat(user.getName()).isNull();
        assertThat(user.getProfileSource()).isNull();
        assertThat(user.getProfileUpdatedAt()).isEqualTo(T2);
    }

    @Test
    void sameProviderDataTwiceChangesNothing() {
        User user = newUser();
        user.applyProviderProfile(GOOGLE, T1);

        boolean changed = user.applyProviderProfile(GOOGLE, T2);

        assertThat(changed).isFalse();
        assertThat(user.getProfileUpdatedAt()).as("no change, no new timestamp").isEqualTo(T1);
    }

    @Test
    void emptyProviderDataChangesNothing() {
        User user = newUser();

        boolean changed = user.applyProviderProfile(IdentityProfile.fromProvider(null, null, null, null, null), T1);

        assertThat(changed).isFalse();
        assertThat(user.getProfileSource()).isNull();
    }

    private static User newUser() {
        return new User(EmailAddress.of("isuru@example.com"), null);
    }
}
