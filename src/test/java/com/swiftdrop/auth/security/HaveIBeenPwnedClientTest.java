package com.swiftdrop.auth.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/** A fake HIBP server: these tests never call the internet. */
@ExtendWith(OutputCaptureExtension.class)
class HaveIBeenPwnedClientTest {

    // SHA-1("password") = 5BAA6 | 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    private static final String PREFIX_URL = "https://api.pwnedpasswords.com/range/5BAA6";
    private static final String SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
    private static final Duration DEADLINE = Duration.ofSeconds(3);

    private final RestClient.Builder builder = BreachedPasswordCheckConfig.hibpClientBuilder();
    private final MockRestServiceServer hibp = MockRestServiceServer.bindTo(builder).build();
    private final HaveIBeenPwnedClient client = new HaveIBeenPwnedClient(builder.build(), DEADLINE);

    @Test
    void sendsOnlyTheHashPrefixWithPaddingAndUserAgentAndDetectsABreach() {
        hibp.expect(requestTo(PREFIX_URL))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Add-Padding", "true"))
                .andExpect(header("User-Agent", BreachedPasswordCheckConfig.USER_AGENT))
                .andRespond(withSuccess("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n" + SUFFIX + ":52579\r\n",
                        MediaType.TEXT_PLAIN));

        assertThat(client.check("password").isCompromised()).isTrue();
        hibp.verify();
    }

    @Test
    void passwordNotInTheListIsNotCompromised() {
        hibp.expect(requestTo(PREFIX_URL))
                .andRespond(withSuccess("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n", MediaType.TEXT_PLAIN));

        assertThat(client.check("password").isCompromised()).isFalse();
    }

    @Test
    void paddingRowsWithCountZeroAreIgnored() {
        hibp.expect(requestTo(PREFIX_URL)).andRespond(withSuccess(SUFFIX + ":0\r\n", MediaType.TEXT_PLAIN));

        assertThat(client.check("password").isCompromised()).isFalse();
    }

    @Test
    void outageFailsOpenAndNeverLogsTheHashPrefix(CapturedOutput output) {
        hibp.expect(requestTo(PREFIX_URL)).andRespond(withServerError());

        assertThat(client.check("password").isCompromised()).isFalse();
        assertThat(output).contains("Breached-password check unavailable").doesNotContain("5BAA6");
    }

    @Test
    void slowServerIsCutOffAtTheDeadline() {
        RestClient slow = RestClient.builder()
                .baseUrl(BreachedPasswordCheckConfig.API_URL)
                .requestFactory((uri, httpMethod) -> {
                    sleep(Duration.ofSeconds(5));
                    return new MockClientHttpRequest(httpMethod, uri);
                })
                .build();
        HaveIBeenPwnedClient withShortDeadline = new HaveIBeenPwnedClient(slow, Duration.ofMillis(200));

        long start = System.nanoTime();
        boolean compromised = withShortDeadline.check("password").isCompromised();

        assertThat(compromised).isFalse();
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
