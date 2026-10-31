package com.swiftdrop.auth.verification;

import com.swiftdrop.auth.user.EmailAddress;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import java.net.URI;

/** SMTP adapter (Mailpit in development). Plain text, minimal content: a link and nothing personal. */
@Component
class SmtpAccountEmailSender implements AccountEmailSender {

    static final String VERIFY_SUBJECT = "Verify your SwiftDrop email address";
    static final String ALREADY_REGISTERED_SUBJECT = "You already have a SwiftDrop account";

    private final JavaMailSender mail;
    private final String from;

    SmtpAccountEmailSender(JavaMailSender mail, @Value("${swiftdrop.mail.from}") String from) {
        this.mail = mail;
        this.from = from;
    }

    @Override
    public void sendVerification(EmailAddress to, URI verificationLink) {
        send(to, VERIFY_SUBJECT, """
                Welcome to SwiftDrop.

                Open this link and press "Confirm" to verify your email address:
                %s

                The link works once and expires in 24 hours. If you did not sign up, ignore this email.
                """.formatted(verificationLink));
    }

    @Override
    public void sendAlreadyRegistered(EmailAddress to, URI loginLink) {
        send(to, ALREADY_REGISTERED_SUBJECT, """
                Someone (hopefully you) tried to create a SwiftDrop account with this email address,
                but you already have one. You can log in here:
                %s

                If this wasn't you, you can ignore this email. Your account has not been changed.
                """.formatted(loginLink));
    }

    private void send(EmailAddress to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to.value());
        message.setSubject(subject);
        message.setText(body);
        mail.send(message);
    }
}
