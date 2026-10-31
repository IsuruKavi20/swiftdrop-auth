package com.swiftdrop.auth.security;

import com.swiftdrop.auth.common.concurrency.Bulkhead;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;

@Configuration
public class PasswordEncoderConfig {

    // Stored hashes look like "{argon2}$argon2id$...": the id lets us change algorithm later
    // while still verifying old hashes.
    private static final String CURRENT_ENCODER_ID = "argon2";

    @Bean
    PasswordEncoder passwordEncoder(PasswordHashingProperties settings) {
        PasswordEncoder argon2 = new Argon2PasswordEncoder(
                settings.saltLengthBytes(), settings.hashLengthBytes(), settings.parallelism(),
                settings.memoryKb(), settings.iterations());
        return new DelegatingPasswordEncoder(CURRENT_ENCODER_ID, Map.of(CURRENT_ENCODER_ID, argon2));
    }

    /** Shared by signup now and login later: caps concurrent breach checks + Argon2 hashes. */
    @Bean
    Bulkhead passwordWorkBulkhead(PasswordWorkProperties limits) {
        return new Bulkhead(limits.maxConcurrent(), limits.maxWait());
    }
}
