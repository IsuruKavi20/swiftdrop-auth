package com.swiftdrop.auth.account;

import com.swiftdrop.auth.user.EmailAddress;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import java.net.URI;

import static com.swiftdrop.auth.account.SmtpAccountEmailSubjects.ADDRESS_ALREADY_USED;
import static com.swiftdrop.auth.account.SmtpAccountEmailSubjects.CHANGE_REQUESTED;
import static com.swiftdrop.auth.account.SmtpAccountEmailSubjects.CONFIRM_NEW_EMAIL;
import static com.swiftdrop.auth.account.SmtpAccountEmailSubjects.EMAIL_CHANGED;
import static com.swiftdrop.auth.account.SmtpAccountEmailSubjects.PASSWORD_CHANGED;
import static com.swiftdrop.auth.account.SmtpAccountEmailSubjects.PASSWORD_RESET;

/** SMTP adapter (Mailpit in development, Brevo in production). Plain text, a link and nothing personal. */
@Component
class SmtpSecurityEmails implements SecurityEmails {

    private final JavaMailSender mail;
    private final String from;

    SmtpSecurityEmails(JavaMailSender mail, @Value("${swiftdrop.mail.from}") String from) {
        this.mail = mail;
        this.from = from;
    }

    @Override
    public void sendConfirmNewEmail(EmailAddress to, URI confirmLink) {
        send(to, CONFIRM_NEW_EMAIL, """
                Someone (hopefully you) asked to use this address for their SwiftDrop account.

                Open this link and press "Confirm" to make it your login email:
                %s

                The link works once and expires in 1 hour. If you did not ask for this, ignore this email:
                nothing changes without your confirmation.
                """.formatted(confirmLink));
    }

    @Override
    public void sendAddressAlreadyUsed(EmailAddress to) {
        send(to, ADDRESS_ALREADY_USED, """
                Someone asked to use this address for a SwiftDrop account, but it already belongs to an account,
                so nothing was changed.

                If this was you, log in with this address instead. If not, you can ignore this email.
                """);
    }

    @Override
    public void sendChangeRequested(EmailAddress to, String maskedNewEmail) {
        send(to, CHANGE_REQUESTED, """
                A change of your SwiftDrop login email to %s was requested.

                It only happens if the new address confirms it. If this wasn't you, change your password now:
                someone may know it.
                """.formatted(maskedNewEmail));
    }

    @Override
    public void sendEmailChanged(EmailAddress to, String maskedNewEmail, URI undoLink) {
        send(to, EMAIL_CHANGED, """
                Your SwiftDrop login email was changed to %s.

                If this wasn't you, open this link to undo it. It also logs everyone out of your account:
                %s

                The link works once, for 3 days. Then log in with this address and change your password.
                """.formatted(maskedNewEmail, undoLink));
    }

    @Override
    public void sendPasswordChanged(EmailAddress to) {
        send(to, PASSWORD_CHANGED, """
                Your SwiftDrop password was just changed, and every other device was logged out.

                If this was not you, someone has access to your account: contact SwiftDrop support right away.
                """);
    }

    @Override
    public void sendPasswordReset(EmailAddress to, URI resetLink) {
        send(to, PASSWORD_RESET, """
                Someone (hopefully you) asked to reset the password of your SwiftDrop account.

                Open this link and choose a new password:
                %s

                The link works once and expires in 30 minutes. Choosing a new password logs you out everywhere.
                If you did not ask for this, ignore this email: your password stays the same.
                """.formatted(resetLink));
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
