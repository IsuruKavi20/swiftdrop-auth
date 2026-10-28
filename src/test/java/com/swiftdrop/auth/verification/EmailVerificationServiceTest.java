package com.swiftdrop.auth.verification;

import com.swiftdrop.auth.common.web.FrontendProperties;
import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.User;
import com.swiftdrop.auth.user.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EmailVerificationServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-24T10:00:00Z");
    private static final Duration TTL = Duration.ofHours(24);
    private static final Duration COOLDOWN = Duration.ofSeconds(60);
    private static final int MAX_PER_DAY = 5;
    private static final URI FRONTEND = URI.create("https://app.swiftdrop.dev");
    private static final UUID USER_ID = UUID.randomUUID();
    private static final UUID TOKEN_ID = UUID.randomUUID();

    @Mock
    private UserRepository users;

    @Mock
    private VerificationTokenRepository tokens;

    @Mock
    private AccountEmailSender sender;

    @Mock
    private ApplicationEventPublisher events;

    private EmailVerificationService service;

    @BeforeEach
    void setUp() {
        service = new EmailVerificationService(users, tokens, sender, events,
                new VerificationProperties(TTL, COOLDOWN, MAX_PER_DAY), new FrontendProperties(FRONTEND),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void issuingStoresOnlyTheHashAndEmailsALinkWithTheTokenInTheFragment() {
        when(users.findById(USER_ID)).thenReturn(Optional.of(user(false)));

        service.issueVerification(USER_ID);

        ArgumentCaptor<VerificationToken> saved = ArgumentCaptor.forClass(VerificationToken.class);
        verify(tokens).save(saved.capture());
        ArgumentCaptor<URI> link = ArgumentCaptor.forClass(URI.class);
        verify(sender).sendVerification(any(EmailAddress.class), link.capture());

        String token = link.getValue().getFragment().substring("token=".length());
        assertThat(link.getValue().toString()).startsWith("https://app.swiftdrop.dev/verify-email#token=");
        assertThat(saved.getValue().getTokenHash()).isEqualTo(VerificationTokens.hash(token)).isNotEqualTo(token);
        assertThat(saved.getValue().getCreatedAt()).isEqualTo(NOW);
        assertThat(saved.getValue().getExpiresAt()).isEqualTo(NOW.plus(TTL));
        verify(tokens).invalidateOpenTokens(USER_ID, NOW);
    }

    @Test
    void noNewEmailWithinTheCooldownSoInboxesCannotBeFlooded() {
        when(users.findById(USER_ID)).thenReturn(Optional.of(user(false)));
        when(tokens.existsByUserIdAndCreatedAtAfter(USER_ID, NOW.minus(COOLDOWN))).thenReturn(true);

        service.issueVerification(USER_ID);

        verify(tokens, never()).save(any());
        verifyNoInteractions(sender);
    }

    @Test
    void noMoreThanFiveEmailsPerDay() {
        when(users.findById(USER_ID)).thenReturn(Optional.of(user(false)));
        when(tokens.countByUserIdAndCreatedAtAfter(USER_ID, NOW.minus(Duration.ofDays(1)))).thenReturn(5L);

        service.issueVerification(USER_ID);

        verify(tokens, never()).save(any());
        verifyNoInteractions(sender);
    }

    @Test
    void alreadyVerifiedUserGetsNoNewToken() {
        when(users.findById(USER_ID)).thenReturn(Optional.of(user(true)));

        service.issueVerification(USER_ID);

        verify(tokens, never()).save(any());
        verifyNoInteractions(sender);
    }

    @Test
    void deletedUserIsIgnoredSoARedeliveredEventCannotLoopForever() {
        when(users.findById(USER_ID)).thenReturn(Optional.empty());

        service.issueVerification(USER_ID);

        verifyNoInteractions(sender);
    }

    @Test
    void signupAttemptOnVerifiedAccountSendsAlreadyRegisteredMail() {
        when(users.findById(USER_ID)).thenReturn(Optional.of(user(true)));

        service.handleSignupAttemptOnExistingAccount(USER_ID);

        verify(sender).sendAlreadyRegistered(any(EmailAddress.class), any(URI.class));
    }

    @Test
    void signupAttemptOnUnverifiedAccountSendsAFreshVerificationInstead() {
        when(users.findById(USER_ID)).thenReturn(Optional.of(user(false)));

        service.handleSignupAttemptOnExistingAccount(USER_ID);

        verify(sender).sendVerification(any(EmailAddress.class), any(URI.class));
        verify(sender, never()).sendAlreadyRegistered(any(), any());
    }

    @Test
    void validTokenIsConsumedAtomicallyAndVerifiesTheUser() {
        String token = VerificationTokens.newToken();
        User user = user(false);
        when(tokens.findByTokenHash(VerificationTokens.hash(token))).thenReturn(Optional.of(stored(token)));
        when(tokens.consumeIfUsable(TOKEN_ID, NOW)).thenReturn(1);
        when(users.findById(USER_ID)).thenReturn(Optional.of(user));

        service.verify(token);

        assertThat(user.isEmailVerified()).isTrue();
    }

    @Test
    void tokenThatIsUsedExpiredOrJustConsumedByAConcurrentRequestIsRejected() {
        String token = VerificationTokens.newToken();
        when(tokens.findByTokenHash(VerificationTokens.hash(token))).thenReturn(Optional.of(stored(token)));
        when(tokens.consumeIfUsable(TOKEN_ID, NOW)).thenReturn(0);

        assertThatThrownBy(() -> service.verify(token)).isInstanceOf(InvalidVerificationTokenException.class);
        verify(users, never()).findById(any());
    }

    @Test
    void unknownTokenIsRejected() {
        when(tokens.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.verify(VerificationTokens.newToken()))
                .isInstanceOf(InvalidVerificationTokenException.class);
        verify(tokens, never()).consumeIfUsable(any(), eq(NOW));
    }

    @Test
    void malformedTokenIsRejectedWithoutTouchingTheDatabase() {
        assertThatThrownBy(() -> service.verify("not-a-token")).isInstanceOf(InvalidVerificationTokenException.class);

        verifyNoInteractions(tokens);
    }

    @Test
    void resendForUnknownEmailDoesNothingAndDoesNotFail() {
        when(users.findByEmail("nobody@x.com")).thenReturn(Optional.empty());

        service.requestResend("nobody@x.com");

        verifyNoInteractions(events);
    }

    @Test
    void resendForUnverifiedUserPublishesARequest() {
        User user = user(false);
        when(users.findByEmail("isuru@x.com")).thenReturn(Optional.of(user));

        service.requestResend("Isuru@X.com");

        verify(events).publishEvent(new VerificationEmailRequested(user.getId()));
    }

    private static VerificationToken stored(String token) {
        VerificationToken stored = new VerificationToken(USER_ID, VerificationTokens.hash(token), NOW.minusSeconds(60),
                NOW.plusSeconds(60));
        org.springframework.test.util.ReflectionTestUtils.setField(stored, "id", TOKEN_ID);
        return stored;
    }

    private static User user(boolean verified) {
        User user = new User(EmailAddress.of("isuru@x.com"), "{argon2}hash");
        if (verified) {
            user.markEmailVerified();
        }
        return user;
    }
}
