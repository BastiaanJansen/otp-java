package com.bastiaanjansen.otp;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.hamcrest.MatcherAssert.assertThat;

class TOTPGeneratorTest {

    private final static String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    private static Stream<Arguments> secondsPast1970TestData() {
        return Stream.of(
                Arguments.of(6, 1, HMACAlgorithm.SHA1, "455216"),
                Arguments.of(7, 1, HMACAlgorithm.SHA1, "7455216"),
                Arguments.of(8, 1, HMACAlgorithm.SHA1, "17455216"),

                Arguments.of(6, 1000, HMACAlgorithm.SHA1, "687469"),
                Arguments.of(6, 923892, HMACAlgorithm.SHA1, "909546"),
                Arguments.of(6, 82764924, HMACAlgorithm.SHA1, "408978"),

                Arguments.of(6, 1, HMACAlgorithm.SHA256, "755370"),
                Arguments.of(6, 1, HMACAlgorithm.SHA512, "303161")
        );
    }

    private static Stream<Arguments> instantTestData() {
        return Stream.of(
                Arguments.of(6, Instant.ofEpochSecond(1), HMACAlgorithm.SHA1, "455216"),
                Arguments.of(7, Instant.ofEpochSecond(1000), HMACAlgorithm.SHA1, "0687469"),
                Arguments.of(8, Instant.ofEpochSecond(923892), HMACAlgorithm.SHA1, "39909546"),
                Arguments.of(6, Instant.ofEpochSecond(82764924), HMACAlgorithm.SHA256, "999993"),
                Arguments.of(6, Instant.ofEpochSecond(82764924), HMACAlgorithm.SHA512, "300089")
        );
    }

    private static Stream<Arguments> dateTestData() {
        return Stream.of(
                Arguments.of(6, Date.from(Instant.ofEpochSecond(1)), HMACAlgorithm.SHA1, "455216"),
                Arguments.of(7, Date.from(Instant.ofEpochSecond(100)), HMACAlgorithm.SHA1, "9650012"),
                Arguments.of(8, Date.from(Instant.ofEpochSecond(723)), HMACAlgorithm.SHA1, "12251322"),
                Arguments.of(6, Date.from(Instant.ofEpochSecond(123)), HMACAlgorithm.SHA256, "376047"),
                Arguments.of(6, Date.from(Instant.ofEpochSecond(9802467)), HMACAlgorithm.SHA512, "040816")
        );
    }

    private static Stream<Arguments> clockTestData() {
        return Stream.of(
                Arguments.of(6, Clock.fixed(Instant.ofEpochSecond(1), ZoneId.of("UTC")), HMACAlgorithm.SHA1, "455216"),
                Arguments.of(7, Clock.fixed(Instant.ofEpochSecond(100), ZoneId.of("UTC")), HMACAlgorithm.SHA1, "9650012"),
                Arguments.of(8, Clock.fixed(Instant.ofEpochSecond(723), ZoneId.of("UTC")), HMACAlgorithm.SHA1, "12251322"),
                Arguments.of(6, Clock.fixed(Instant.ofEpochSecond(123), ZoneId.of("UTC")), HMACAlgorithm.SHA256, "376047"),
                Arguments.of(6, Clock.fixed(Instant.ofEpochSecond(9802467), ZoneId.of("UTC")), HMACAlgorithm.SHA512, "040816")
        );
    }

    @ParameterizedTest
    @MethodSource("secondsPast1970TestData")
    void generateAtSecondsPast1970(int passwordLength, int secondsPast1970, HMACAlgorithm algorithm, String otp) {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> {
            builder.withPasswordLength(passwordLength);
            builder.withAlgorithm(algorithm);
        }).build();

        assertThat(generator.at(secondsPast1970), is(otp));
    }

    @ParameterizedTest
    @MethodSource("instantTestData")
    void generateAtInstant(int passwordLength, Instant instant, HMACAlgorithm algorithm, String otp) {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> {
            builder.withPasswordLength(passwordLength);
            builder.withAlgorithm(algorithm);
        }).build();

        assertThat(generator.at(instant), is(otp));
    }

    @ParameterizedTest
    @MethodSource("dateTestData")
    void generateAtDate(int passwordLength, Date date, HMACAlgorithm algorithm, String otp) {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> {
            builder.withPasswordLength(passwordLength);
            builder.withAlgorithm(algorithm);
        }).build();

        assertThat(generator.at(date), is(otp));
    }

    @ParameterizedTest
    @MethodSource("clockTestData")
    void generateAtNow(int passwordLength, Clock clock, HMACAlgorithm algorithm, String otp) {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> {
                    builder.withPasswordLength(passwordLength);
                    builder.withAlgorithm(algorithm);
                })
                .withClock(clock)
                .build();

        assertThat(generator.now(), is(otp));
    }


    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void generateWithInvalidSecondsPast1970_throwsIllegalArgumentException(int secondsPast1970) {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();

        assertThrows(IllegalArgumentException.class, () -> generator.at(secondsPast1970));
    }


//    @Test
//    void verifyCurrentCode_true() {
//        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
//        String code = generator.now();
//
//        assertThat(generator.verify(code), is(true));
//    }
//
//    @Test
//    void verifyOlderCodeWithDelayWindowIs0_false() {
//        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
//        String code = generator.at(Instant.now().minusSeconds(30));
//
//        assertThat(generator.verify(code), is(false));
//    }
//
//    @Test
//    void verifyOlderCodeWithDelayWindowIs1_true() {
//        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
//        String code = generator.at(Instant.now().minusSeconds(30));
//
//        assertThat(generator.verify(code, 1), is(true));
//    }


    @Test
    void getURIWithIssuer() throws URISyntaxException {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();

        URI uri = generator.getURI("issuer");
        assertThat(uri.toString(), is("otpauth://totp/issuer?period=30&digits=6&secret=" + secret + "&issuer=issuer&algorithm=SHA1"));
    }

    @Test
    void getURIWithIssuerWithUrlUnsafeCharacters() throws URISyntaxException {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();

        URI uri = generator.getURI("mac&cheese");
        assertThat(uri.toString(), is("otpauth://totp/mac&cheese?period=30&digits=6&secret=" + secret + "&issuer=mac%26cheese&algorithm=SHA1"));
    }

    @Test
    void getURIWithIssuerAndAccount_doesNotThrow() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();

        assertDoesNotThrow(() -> {
            generator.getURI("issuer", "account");
        });
    }

    @Test
    void getURIWithIssuerAndAccount() throws URISyntaxException {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();


        URI uri = generator.getURI("issuer", "account");
        assertThat(uri.toString(), is("otpauth://totp/issuer:account?period=30&digits=6&secret=" + secret + "&issuer=issuer&algorithm=SHA1"));
    }

    @Test
    void getURIWithIssuerAndAccountWithUrlUnsafeCharacters() throws URISyntaxException {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();


        URI uri = generator.getURI("mac&cheese", "ac@cou.nt");
        assertThat(uri.toString(), is("otpauth://totp/mac&cheese:ac@cou.nt?period=30&digits=6&secret=" + secret + "&issuer=mac%26cheese&algorithm=SHA1"));
    }

    @Test
    void fromURIWithPeriod() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?period=60&secret=" + secret);

        TOTPGenerator generator = TOTPGenerator.fromURI(uri);
        Duration expected = Duration.ofSeconds(60);

        assertThat(generator.getPeriod(), is(expected));
    }

    @Test
    void fromURIWithAlgorithmUppercase() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=SHA1&secret=" + secret);

        TOTPGenerator generator = TOTPGenerator.fromURI(uri);
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void fromURIWithAlgorithmLowercase() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=sha1&secret=" + secret);

        TOTPGenerator generator = TOTPGenerator.fromURI(uri);
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void fromURIWithPasswordLength() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=6&secret=" + secret);

        TOTPGenerator generator = TOTPGenerator.fromURI(uri);
        int expected = 6;

        assertThat(generator.getPasswordLength(), is(expected));
    }

    @Test
    void fromURIWithInvalidPeriod_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?period=invalid&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> TOTPGenerator.fromURI(uri));
    }

    @Test
    void fromURIWithPasswordLengthIs5_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=5&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> TOTPGenerator.fromURI(uri));
    }

    @Test
    void fromURIWithPasswordLengthIs9_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=9&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> TOTPGenerator.fromURI(uri));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "otpauth://totp/issuer:account?digits=6&secret=",
            "otpauth://totp/issuer:account?digits=8&secret=",
            "otpauth://totp/issuer:account?digits=7&secret="
    })
    void fromURI_doesNotThrow(String url) throws URISyntaxException {
        URI uri = new URI(url + secret);

        assertDoesNotThrow(() -> {
            TOTPGenerator.fromURI(uri);
        });
    }

    @Test
    void fromURIWithInvalidAlgorithm_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=invalid&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> TOTPGenerator.fromURI(uri));
    }

    @Nested
    class BuilderTest {
        @Test
        void builderWithEmptySecret_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> new TOTPGenerator.Builder(new byte[]{}).build());
        }

        @Test
        void builderWithPasswordLengthIs5_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> {
                new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> builder.withPasswordLength(5)).build();
            });
        }

        @Test
        void builderWithPasswordLengthIs9_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> {
                new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> builder.withPasswordLength(9)).build();
            });
        }

        @Test
        void builderWithPasswordLengthIs6() {
            TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> builder.withPasswordLength(6)).build();
            int expected = 6;

            assertThat(generator.getPasswordLength(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA1() {
            TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> builder.withAlgorithm(HMACAlgorithm.SHA1)).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA1;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA256() {
            TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> builder.withAlgorithm(HMACAlgorithm.SHA256)).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA256;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA512() {
            TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> builder.withAlgorithm(HMACAlgorithm.SHA512)).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA512;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @ParameterizedTest
        @ValueSource(ints = {1, 2, 3, 4, 5, 9, 10})
        void builderWithInvalidPasswordLength_throwsIllegalArgumentException(int passwordLength) {
            assertThrows(IllegalArgumentException.class, () -> new TOTPGenerator.Builder(secret.getBytes()).withHOTPGenerator(builder -> builder.withPasswordLength(passwordLength)).build());
        }

        @Test
        void builderWithoutPeriod_defaultPeriod() {
            TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
            Duration expected = Duration.ofSeconds(30);

            assertThat(generator.getPeriod(), is(expected));
        }

        @Test
        void builderWithoutAlgorithm_defaultAlgorithm() {
            TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA1;

            assertThat(generator.getAlgorithm(), is(expected));
        }
    }
}
