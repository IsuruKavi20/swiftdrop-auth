package com.swiftdrop.auth.user.api;

import com.swiftdrop.auth.TestcontainersConfiguration;
import com.swiftdrop.auth.token.AccessTokenIssuer;
import com.swiftdrop.auth.token.TestPeople;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.IdentityProfile;
import com.swiftdrop.auth.user.PersonName;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Identity step 4c: the OpenID Connect UserInfo endpoint (OIDC Core 5.3). */
@Import(TestcontainersConfiguration.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class UserInfoIT {

    private static final String USERINFO = "/oauth2/userinfo";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository users;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private AccessTokenIssuer issuer;

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void answersWhoTheAccessTokenIsForWithStandardClaims() throws Exception {
        UUID id = namedUser();

        mockMvc.perform(get(USERINFO).header("Authorization", bearer(id)))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(jsonPath("$.sub").value(id.toString()))
                .andExpect(jsonPath("$.name").value("Nimal Perera"))
                .andExpect(jsonPath("$.email_verified").value(true));
    }

    @Test
    void postIsAllowedToo() throws Exception {
        UUID id = namedUser();

        mockMvc.perform(post(USERINFO).header("Authorization", bearer(id))).andExpect(status().isOk());
    }

    @Test
    void noTokenOrAnInactiveAccountGetsNothing() throws Exception {
        UUID id = namedUser();
        jdbc.update("UPDATE identity.users SET status = 'DISABLED' WHERE id = ?", id);

        mockMvc.perform(get(USERINFO)).andExpect(status().isUnauthorized());
        mockMvc.perform(get(USERINFO).header("Authorization", bearer(id))).andExpect(status().isUnauthorized());
    }

    private String bearer(UUID userId) {
        return "Bearer " + issuer.issue(userId, TestPeople.SOMEONE, List.of("CUSTOMER"), List.of()).value();
    }

    private UUID namedUser() {
        return transactions.execute(status -> {
            User user = new User(EmailAddress.of("userinfo-" + UUID.randomUUID() + "@example.com"), null);
            user.markEmailVerified();
            user.setOwnProfile(IdentityProfile.ofName(PersonName.of("Nimal Perera")), Instant.now());
            return users.saveAndFlush(user).getId();
        });
    }
}
