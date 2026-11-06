package com.swiftdrop.auth.applications;

import com.swiftdrop.auth.user.EmailAddress;
import com.swiftdrop.auth.user.RoleName;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import java.util.Locale;

/** The decision emails to an applicant (identity step 7c). Plain text; the reason is the approver's own words. */
@Component
class ApplicationEmails {

    private final JavaMailSender mail;
    private final String from;

    ApplicationEmails(JavaMailSender mail, @Value("${swiftdrop.mail.from}") String from) {
        this.mail = mail;
        this.from = from;
    }

    void sendApproved(EmailAddress to, RoleName role) {
        send(to, ApplicationEmailSubjects.APPROVED, """
                Good news: your application to become a %s on SwiftDrop was approved.

                Log in again (or wait a few minutes) and the new role will be active in the app.
                """.formatted(roleWord(role)));
    }

    void sendRejected(EmailAddress to, RoleName role, String reason) {
        String why = reason == null ? "No reason was given." : "The reason given: " + reason;
        send(to, ApplicationEmailSubjects.REJECTED, """
                Your application to become a %s on SwiftDrop was not approved this time.

                %s

                You can apply again 7 days after this decision.
                """.formatted(roleWord(role), why));
    }

    private static String roleWord(RoleName role) {
        return role.name().toLowerCase(Locale.ROOT);
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
