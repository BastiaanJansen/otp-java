package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.instanceOf;

class TOTPGeneratorTest {

    private final String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    @Test
    void constructor_instanceOfTOTPGenerator() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();

        assertThat(generator, instanceOf(TOTPGenerator.class));
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
        String expected = "17455216";

        String code = generator.generate(1);

        assertThat(code, is(expected));
    }

    @Test
    void generateWithInstant() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
        String expected = "455216";

        String code = generator.generate(Instant.ofEpochSecond(1));

        assertThat(code, is(expected));
    }

    @Test
    void generateWithDate() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret.getBytes()).build();
        Date date = new GregorianCalendar(2014, Calendar.FEBRUARY, 11).getTime();
        String expected = "019287";

        String code = generator.generate(date);

        assertThat(code, is(expected));
    }

    @Test
    void generateWithPeriodOfZero() {
        assertThrows(IllegalArgumentException.class, () -> {
            new TOTPGenerator.Builder(secret.getBytes()).withPeriod(Duration.ofSeconds(0)).build();
        });
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

        assertThrows(URISyntaxException.class, () -> {
            TOTPGenerator.Builder.fromOTPAuthURI(uri);
        });
    }

    @Test
    void fromURIWithDigitsIs5_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=5&secret=" + secret);

        assertThrows(IllegalArgumentException.class, () -> {
            TOTPGenerator.Builder.fromOTPAuthURI(uri);
        });
    }

    @Test
    void fromURIWithDigitsIs9_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?digits=9&secret=" + secret);

        assertThrows(IllegalArgumentException.class, () -> {
            TOTPGenerator.Builder.fromOTPAuthURI(uri);
        });
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

        assertThrows(URISyntaxException.class, () -> {
            TOTPGenerator.Builder.fromOTPAuthURI(uri);
        });
    }
}