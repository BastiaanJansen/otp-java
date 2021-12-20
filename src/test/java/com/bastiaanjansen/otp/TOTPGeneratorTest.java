package com.bastiaanjansen.otp;

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
import static org.hamcrest.CoreMatchers.instanceOf;

class TOTPGeneratorTest {

    private final String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    @Test
    void constructor_instanceOfTOTPGenerator() {
        TOTPGenerator generator = new TOTPGenerator(6, Duration.ofSeconds(30), HMACAlgorithm.SHA1, secret.getBytes());

        assertThat(generator, instanceOf(TOTPGenerator.class));
    }

    @Test
    void constructorWithInvalidPasswordLength_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new TOTPGenerator(5, Duration.ofSeconds(30), HMACAlgorithm.SHA1, secret.getBytes()));
    }

    @Test
    void generateBasedOnSecondsPast1970() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
        String expected = "455216";

        String code = generator.generate(1);

        assertThat(code, is(expected));
    }

    @Test
    void generateWithEightDigits() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).withPasswordLength(8).build();
        int expected = 8;

        String code = generator.generate(1);

        assertThat(code.length(), is(expected));
    }

    @Test
    void generateWithInstant() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
        String expected = "455216";

        String code = generator.generate(Instant.ofEpochSecond(1));

        assertThat(code, is(expected));
    }

    @Test
    void generateWithSeconds() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
        String expected = "650012";

        String code = generator.generate(100);

        assertThat(code, is(expected));
    }

    @Test
    void generateWithDate() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
        int secondsSince1970 = 100;
        Date date = new Date(secondsSince1970 * 1000);
        String expected = "650012";

        String code = generator.generate(date);

        assertThat(code, is(expected));
    }

    @Test
    void generateWithInvalidSeconds_throwsIllegalArgumentException() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();

        assertThrows(IllegalArgumentException.class, () -> generator.generate(-1));
    }

    @Test
    void generateWithPeriodOfZero() {
        assertThrows(IllegalArgumentException.class, () -> new TOTPGenerator.Builder(secret.getBytes()).withPeriod(Duration.ofSeconds(0)).build());
    }

    @Test
    void builderDefaultValues_period() {
        TOTPGenerator generator = TOTPGenerator.Builder.withDefaultValues(secret.getBytes());
        Duration expected = Duration.ofSeconds(30);

        assertThat(generator.getPeriod(), is(expected));
    }

    @Test
    void builderDefaultValues_algorithm() {
        TOTPGenerator generator = TOTPGenerator.Builder.withDefaultValues(secret.getBytes());
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void builderDefaultValues_passwordLength() {
        TOTPGenerator generator = TOTPGenerator.Builder.withDefaultValues(secret.getBytes());
        int expected = 6;

        assertThat(generator.getPasswordLength(), is(expected));
    }

    @Test
    void generateFromCurrentTime() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
        long secondsPast1970 = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
        String expected = generator.generate(secondsPast1970);

        assertThat(generator.generate(), is(expected));
    }

    @Test
    void verifyCurrentCode_true() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
        String code = generator.generate();
        boolean expected = true;

        assertThat(generator.verify(code), is(expected));
    }

    @Test
    void verifyOlderCodeWithDelayWindowIs0_false() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
        String code = generator.generate(Instant.now().minusSeconds(30));
        boolean expected = false;

        assertThat(generator.verify(code), is(expected));
    }

    @Test
    void verifyOlderCodeWithDelayWindowIs1_true() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
        String code = generator.generate(Instant.now().minusSeconds(30));
        boolean expected = true;

        assertThat(generator.verify(code, 1), is(expected));
    }

    @Test
    void getURIWithIssuer_doesNotThrow() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();

        assertDoesNotThrow(() -> {
            generator.getURI("issuer");
        });
    }

    @Test
    void getURIWithIssuer() throws URISyntaxException {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();

        URI uri = generator.getURI("issuer");
        assertThat(uri.toString(), is("otpauth://totp/issuer?period=30&digits=6&secret=" + secret + "&algorithm=SHA1"));
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
        assertThat(uri.toString(), is("otpauth://totp/issuer:account?period=30&digits=6&secret=" + secret + "&algorithm=SHA1"));
    }

    @Test
    void fromURIWithPeriod() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?period=60&secret=" + secret);

        TOTPGenerator generator = TOTPGenerator.Builder.fromOTPAuthURI(uri);
        Duration expected = Duration.ofSeconds(60);

        assertThat(generator.getPeriod(), is(expected));
    }

    @Test
    void fromURIWithAlgorithmUppercase() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=SHA1&secret=" + secret);

        TOTPGenerator generator = TOTPGenerator.Builder.fromOTPAuthURI(uri);
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void fromURIWithAlgorithmLowercase() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=sha1&secret=" + secret);

        TOTPGenerator generator = TOTPGenerator.Builder.fromOTPAuthURI(uri);
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void fromURIWithDigits() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=6&secret=" + secret);

        TOTPGenerator generator = TOTPGenerator.Builder.fromOTPAuthURI(uri);
        int expected = 6;

        assertThat(generator.getPasswordLength(), is(expected));
    }

    @Test
    void fromURIWithInvalidPeriod_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?period=invalid&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> TOTPGenerator.Builder.fromOTPAuthURI(uri));
    }

    @Test
    void fromURIWithDigitsIs5_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=5&secret=" + secret);

        assertThrows(IllegalArgumentException.class, () -> TOTPGenerator.Builder.fromOTPAuthURI(uri));
    }

    @Test
    void fromURIWithDigitsIs9_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=9&secret=" + secret);

        assertThrows(IllegalArgumentException.class, () -> TOTPGenerator.Builder.fromOTPAuthURI(uri));
    }

    @Test
    void fromURIWithDigitsIs6_doesNotThrow() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=6&secret=" + secret);

        assertDoesNotThrow(() -> {
            TOTPGenerator.Builder.fromOTPAuthURI(uri);
        });
    }

    @Test
    void fromURIWithDigitsIs8_doesNotThrow() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=8&secret=" + secret);

        assertDoesNotThrow(() -> {
            TOTPGenerator.Builder.fromOTPAuthURI(uri);
        });
    }

    @Test
    void fromURIWithDigitsIs7_doesNotThrow() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=7&secret=" + secret);

        assertDoesNotThrow(() -> {
            TOTPGenerator.Builder.fromOTPAuthURI(uri);
        });
    }

    @Test
    void fromURIWithInvalidAlgorithm_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=invalid&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> TOTPGenerator.Builder.fromOTPAuthURI(uri));
    }
}