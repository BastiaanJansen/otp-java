package com.bastiaanjansen.otp;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.hamcrest.MatcherAssert.assertThat;

class TOTPTest {

    private final static String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    @Test
    void generateWithPasswordLengthIs6() {
        OTP generator = new TOTP.Builder(secret.getBytes()).withPasswordLength(6).build();
        int expected = 6;

        assertThat(generator.generate(1).length(), is(expected));
    }

    @Test
    void generateWithPasswordLengthIs7() {
        OTP generator = new TOTP.Builder(secret.getBytes()).withPasswordLength(7).build();
        int expected = 7;

        assertThat(generator.generate(1).length(), is(expected));
    }

    @Test
    void generateWithPasswordLengthIs8() {
        OTP generator = new TOTP.Builder(secret.getBytes()).withPasswordLength(8).build();
        int expected = 8;

        assertThat(generator.generate(1).length(), is(expected));
    }

    @Test
    void generateWithSHA1() {
        OTP generator = new TOTP.Builder(secret.getBytes()).withAlgorithm(HMACAlgorithm.SHA1).build();
        String expected = "560287";

        assertThat(generator.generate(1), is(expected));
    }

    @Test
    void generateWithSHA256() {
        OTP generator = new TOTP.Builder(secret.getBytes()).withAlgorithm(HMACAlgorithm.SHA256).build();
        String expected = "361406";

        assertThat(generator.generate(1), is(expected));
    }

    @Test
    void generateWithSHA512() {
        OTP generator = new TOTP.Builder(secret.getBytes()).withAlgorithm(HMACAlgorithm.SHA512).build();
        String expected = "016738";

        assertThat(generator.generate(1), is(expected));
    }

    @Test
    void generateBasedOnSecondsPast1970() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();
        String expected = "455216";

        String code = generator.at(1);

        assertThat(code, is(expected));
    }

    @Test
    void generateWithInstant() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();
        String expected = "455216";

        String code = generator.at(Instant.ofEpochSecond(1));

        assertThat(code, is(expected));
    }

    @Test
    void generateWithSeconds() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();
        String expected = "650012";

        String code = generator.at(100);

        assertThat(code, is(expected));
    }

    @Test
    void generateWithDate() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();
        int secondsSince1970 = 100;
        Date date = new Date(secondsSince1970 * 1000);
        String expected = "650012";

        String code = generator.at(date);

        assertThat(code, is(expected));
    }

    @Test
    void generateWithInvalidSeconds_throwsIllegalArgumentException() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();

        assertThrows(IllegalArgumentException.class, () -> generator.at(-1));
    }

    @Test
    void generateWithPeriodOfZero() {
        assertThrows(IllegalArgumentException.class, () -> new TOTP.Builder(secret.getBytes()).withPeriod(Duration.ofSeconds(0)).build());
    }

    @Test
    void withDefaultValues_algorithm_period() {
        TOTP generator = TOTP.withDefaultValues(secret.getBytes());
        Duration expected = Duration.ofSeconds(30);

        assertThat(generator.getPeriod(), is(expected));
    }

    @Test
    void withDefaultValues_algorithm() {
        TOTP generator = TOTP.withDefaultValues(secret.getBytes());
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void withDefaultValues_passwordLength() {
        TOTP generator = TOTP.withDefaultValues(secret.getBytes());
        int expected = 6;

        assertThat(generator.getPasswordLength(), is(expected));
    }

    @Test
    void generateFromCurrentTime() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();
        long secondsPast1970 = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
        String expected = generator.at(secondsPast1970);

        assertThat(generator.now(), is(expected));
    }

    @Test
    void verifyCurrentCode_true() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();
        String code = generator.now();

        assertThat(generator.verify(code), is(true));
    }

    @Test
    void verifyOlderCodeWithDelayWindowIs0_false() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();
        String code = generator.at(Instant.now().minusSeconds(30));

        assertThat(generator.verify(code), is(false));
    }

    @Test
    void verifyOlderCodeWithDelayWindowIs1_true() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();
        String code = generator.at(Instant.now().minusSeconds(30));

        assertThat(generator.verify(code, 1), is(true));
    }

    @Test
    void getURIWithIssuer_doesNotThrow() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();

        assertDoesNotThrow(() -> {
            generator.getURI("issuer");
        });
    }

    @Test
    void getURIWithIssuer() throws URISyntaxException {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();

        URI uri = generator.getURI("issuer");
        assertThat(uri.toString(), is("otpauth://totp/issuer?period=30&digits=6&secret=" + secret + "&issuer=issuer&algorithm=SHA1"));
    }

    @Test
    void getURIWithIssuerWithUrlUnsafeCharacters() throws URISyntaxException {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();

        URI uri = generator.getURI("mac&cheese");
        assertThat(uri.toString(), is("otpauth://totp/mac&cheese?period=30&digits=6&secret=" + secret + "&issuer=mac%26cheese&algorithm=SHA1"));
    }

    @Test
    void getURIWithIssuerAndAccount_doesNotThrow() {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();

        assertDoesNotThrow(() -> {
            generator.getURI("issuer", "account");
        });
    }

    @Test
    void getURIWithIssuerAndAccount() throws URISyntaxException {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();


        URI uri = generator.getURI("issuer", "account");
        assertThat(uri.toString(), is("otpauth://totp/issuer:account?period=30&digits=6&secret=" + secret + "&issuer=issuer&algorithm=SHA1"));
    }

    @Test
    void getURIWithIssuerAndAccountWithUrlUnsafeCharacters() throws URISyntaxException {
        TOTP generator = new TOTP.Builder(secret.getBytes()).build();


        URI uri = generator.getURI("mac&cheese", "ac@cou.nt");
        assertThat(uri.toString(), is("otpauth://totp/mac&cheese:ac@cou.nt?period=30&digits=6&secret=" + secret + "&issuer=mac%26cheese&algorithm=SHA1"));
    }

    @Test
    void fromURIWithPeriod() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?period=60&secret=" + secret);

        TOTP generator = TOTP.fromURI(uri);
        Duration expected = Duration.ofSeconds(60);

        assertThat(generator.getPeriod(), is(expected));
    }

    @Test
    void fromURIWithAlgorithmUppercase() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=SHA1&secret=" + secret);

        TOTP generator = TOTP.fromURI(uri);
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void fromURIWithAlgorithmLowercase() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=sha1&secret=" + secret);

        TOTP generator = TOTP.fromURI(uri);
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void fromURIWithPasswordLength() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=6&secret=" + secret);

        TOTP generator = TOTP.fromURI(uri);
        int expected = 6;

        assertThat(generator.getPasswordLength(), is(expected));
    }

    @Test
    void fromURIWithInvalidPeriod_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?period=invalid&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> TOTP.fromURI(uri));
    }

    @Test
    void fromURIWithPasswordLengthIs5_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=5&secret=" + secret);

        assertThrows(IllegalArgumentException.class, () -> TOTP.fromURI(uri));
    }

    @Test
    void fromURIWithPasswordLengthIs9_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=9&secret=" + secret);

        assertThrows(IllegalArgumentException.class, () -> TOTP.fromURI(uri));
    }

    @Test
    void fromURIWithPasswordLengthIs6_doesNotThrow() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=6&secret=" + secret);

        assertDoesNotThrow(() -> {
            TOTP.fromURI(uri);
        });
    }

    @Test
    void fromURIWithPasswordLengthIs8_doesNotThrow() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=8&secret=" + secret);

        assertDoesNotThrow(() -> {
            TOTP.fromURI(uri);
        });
    }

    @Test
    void fromURIWithPasswordLengthIs7_doesNotThrow() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=7&secret=" + secret);

        assertDoesNotThrow(() -> {
            TOTP.fromURI(uri);
        });
    }

    @Test
    void fromURIWithInvalidAlgorithm_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=invalid&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> TOTP.fromURI(uri));
    }

    @Nested
    class BuilderTest {
        @Test
        void builderWithEmptySecret_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> new TOTP.Builder(new byte[]{}).build());
        }

        @Test
        void builderWithPasswordLengthIs5_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> {
                new TOTP.Builder(secret.getBytes()).withPasswordLength(5).build();
            });
        }

        @Test
        void builderWithPasswordLengthIs9_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> {
                new TOTP.Builder(secret.getBytes()).withPasswordLength(9).build();
            });
        }

        @Test
        void builderWithPasswordLengthIs6() {
            OTP generator = new TOTP.Builder(secret.getBytes()).withPasswordLength(6).build();
            int expected = 6;

            assertThat(generator.getPasswordLength(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA1() {
            TOTP generator = new TOTP.Builder(secret.getBytes()).withAlgorithm(HMACAlgorithm.SHA1).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA1;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA256() {
            TOTP generator = new TOTP.Builder(secret.getBytes()).withAlgorithm(HMACAlgorithm.SHA256).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA256;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA512() {
            TOTP generator = new TOTP.Builder(secret.getBytes()).withAlgorithm(HMACAlgorithm.SHA512).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA512;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @Test
        void builderWithInvalidPasswordLength_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> new TOTP.Builder(secret.getBytes()).withPasswordLength(5).build());
        }

        @Test
        void builderWithoutPeriod_defaultPeriod() {
            TOTP generator = new TOTP.Builder(secret.getBytes()).build();
            Duration expected = Duration.ofSeconds(30);

            assertThat(generator.getPeriod(), is(expected));
        }

        @Test
        void builderWithoutAlgorithm_defaultAlgorithm() {
            TOTP generator = new TOTP.Builder(secret.getBytes()).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA1;

            assertThat(generator.getAlgorithm(), is(expected));
        }
    }
}
