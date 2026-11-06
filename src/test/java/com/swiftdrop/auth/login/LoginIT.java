package com.swiftdrop.auth.login;

import com.nimbusds.jose.jwk.RSAKey;
import com.swiftdrop.auth.MailpitClient;
import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.signup.SignupService;
import com.swiftdrop.auth.user.UserRepository;
import com.swiftdrop.auth.verification.EmailVerificationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** End to end: signup → email → verify → login → a token another service can verify with our public key. */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@ActiveProfiles("test")
class LoginIT {

    private static final String PASSWORD = "my parcel arrives on tuesday";
    private static final Pattern TOKEN_IN_LINK = Pattern.compile("#token=([A-Za-z0-9_-]{43})");

    @Autowired
    private SignupService signup;

    @Autowired
    private EmailVerificationService verification;

    @Autowired
    private LoginService login;

    @Autowired
    private UserRepository users;

    @Autowired
    private RSAKey jwtSigningKey;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private MailpitClient mailpit;

    @Test
    void verifiedUserGetsATokenThatVerifiesWithOurPublicKey() throws Exception {
        String email = verifiedUser();

        String token = login.login(email, PASSWORD).accessToken().value();

        NimbusJwtDecoder otherService = NimbusJwtDecoder.withPublicKey(jwtSigningKey.toRSAPublicKey()).build();
        otherService.setJwtValidator(JwtValidators.createAtJwtValidator()
                .issuer("http://localhost").audience("swiftdrop-api").clientId("swiftdrop-web").build());
        Jwt jwt = otherService.decode(token);

        UUID userId = users.findByEmail(email).orElseThrow().getId();
        assertThat(jwt.getSubject()).isEqualTo(userId.toString());
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("CUSTOMER");
        assertThat(jdbc.queryForObject("SELECT last_login_at IS NOT NULL FROM identity.users WHERE id = ?",
                Boolean.class, userId)).isTrue();
    }

    @Test
    void unverifiedUserWithCorrectPasswordIsToldToVerify() {
        String email = uniqueEmail();
        signup.signUp("Test User", email, PASSWORD);

        assertThatThrownBy(() -> login.login(email, PASSWORD)).isInstanceOf(EmailNotVerifiedException.class);
    }

    @Test
    void wrongPasswordAndUnknownEmailGetTheSameAnswer() {
        String email = verifiedUser();

        assertThatThrownBy(() -> login.login(email, "a completely wrong passphrase"))
                .isInstanceOf(InvalidCredentialsException.class);
        assertThatThrownBy(() -> login.login(uniqueEmail(), PASSWORD))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void emailIsCaseInsensitiveAtLogin() {
        String email = verifiedUser();

        assertThat(login.login(email.toUpperCase(), PASSWORD).accessToken().value()).isNotBlank();
    }

    private String verifiedUser() {
        String email = uniqueEmail();
        signup.signUp("Test User", email, PASSWORD);
        Matcher link = TOKEN_IN_LINK.matcher(mailpit.awaitMessageTo(email, "Verify your SwiftDrop email address").text());
        assertThat(link.find()).isTrue();
        verification.verify(link.group(1));
        return email;
    }

    private static String uniqueEmail() {
        return "login-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }
}
