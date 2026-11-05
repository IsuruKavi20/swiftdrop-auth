package com.swiftdrop.auth.user;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The identity profile (OIDC {@code name}, {@code given_name}, {@code family_name}, {@code picture},
 * {@code locale}). Every value is either valid or absent: data from a provider like Google is cleaned here,
 * and anything unusable is dropped instead of failing the login.
 */
public final class IdentityProfile {

    private static final int MAX_PICTURE_URL_LENGTH = 2048;
    private static final int MAX_LOCALE_LENGTH = 35;
    // BCP 47 shape: a 2-3 letter language, then optional script/region/variant subtags
    private static final Pattern LANGUAGE_TAG = Pattern.compile("[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*");

    private final PersonName name;
    private final PersonName givenName;
    private final PersonName familyName;
    private final String pictureUrl;
    private final String locale;

    private IdentityProfile(PersonName name, PersonName givenName, PersonName familyName, String pictureUrl,
                            String locale) {
        this.name = name;
        this.givenName = givenName;
        this.familyName = familyName;
        this.pictureUrl = pictureUrl;
        this.locale = locale;
    }

    /** No profile data at all (e.g. a provider that sent no profile claims). */
    public static IdentityProfile empty() {
        return new IdentityProfile(null, null, null, null, null);
    }

    /** What the user typed themselves (sign-up): the name is already validated. */
    public static IdentityProfile ofName(PersonName name) {
        return new IdentityProfile(name, null, null, null, null);
    }

    /** Claims from an identity provider. All optional; bad values are dropped. */
    public static IdentityProfile fromProvider(String name, String givenName, String familyName, String pictureUrl,
                                               String locale) {
        return new IdentityProfile(PersonName.ofOptional(name).orElse(null),
                PersonName.ofOptional(givenName).orElse(null), PersonName.ofOptional(familyName).orElse(null),
                safePictureUrl(pictureUrl), languageTag(locale));
    }

    public Optional<PersonName> name() {
        return Optional.ofNullable(name);
    }

    public Optional<PersonName> givenName() {
        return Optional.ofNullable(givenName);
    }

    public Optional<PersonName> familyName() {
        return Optional.ofNullable(familyName);
    }

    public Optional<String> pictureUrl() {
        return Optional.ofNullable(pictureUrl);
    }

    public Optional<String> locale() {
        return Optional.ofNullable(locale);
    }

    public boolean isEmpty() {
        return name == null && givenName == null && familyName == null && pictureUrl == null && locale == null;
    }

    // The URL ends up in an <img src> in browsers: https only, a real host, no credentials, bounded length.
    // We store the link but never fetch it on the server (no SSRF). Lowercase "https://" exactly, like the
    // database CHECK: a URL Java accepts must never make the save (and so the login) fail.
    private static String safePictureUrl(String raw) {
        if (raw == null || raw.length() > MAX_PICTURE_URL_LENGTH || !raw.startsWith("https://")) {
            return null;
        }
        try {
            URI uri = new URI(raw);
            boolean safe = uri.getHost() != null && uri.getRawUserInfo() == null;
            return safe ? raw : null;
        } catch (URISyntaxException notAUrl) {
            return null;
        }
    }

    private static String languageTag(String raw) {
        if (raw == null || raw.length() > MAX_LOCALE_LENGTH) {
            return null;
        }
        String candidate = raw.replace('_', '-');
        if (!LANGUAGE_TAG.matcher(candidate).matches()) {
            return null;
        }
        String tag = Locale.forLanguageTag(candidate).toLanguageTag();
        return "und".equals(tag) ? null : tag;
    }

    /** Profile data is personal: never print it. */
    @Override
    public String toString() {
        return "IdentityProfile[redacted]";
    }
}
