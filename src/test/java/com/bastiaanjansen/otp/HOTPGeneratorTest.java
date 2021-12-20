package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HOTPGeneratorTest {

    private final String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    @Test
    void constructor_instanceOfHOTPGenerator() {
        HOTPGenerator generator = new HOTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());

        assertThat(generator, instanceOf(HOTPGenerator.class));
    }

    @Test
    void constructorWithInvalidPasswordLength_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new HOTPGenerator(5, HMACAlgorithm.SHA1, secret.getBytes()));
    }

    @Test
    void generateWithSixDigits() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        String expected = "560287";

        assertThat(generator.generateCode(1), is(expected));
    }

    @Test
    void generateWithSevenDigits() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).withPasswordLength(7).build();
        int expected = 7;

        assertThat(generator.generateCode(1).length(), is(expected));
    }

    @Test
    void generateWithEightDigits() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).withPasswordLength(8).build();
        int expected = 8;

        assertThat(generator.generateCode(1).length(), is(expected));
    }

    @Test
    void builderWithAlgorithm_isSHA256() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).withAlgorithm(HMACAlgorithm.SHA256).build();
        HMACAlgorithm expected = HMACAlgorithm.SHA256;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void builderWithDigits_is7() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).withPasswordLength(7).build();
        int expected = 7;

        assertThat(generator.getPasswordLength(), is(expected));
    }

    @Test
    void builderDefaultValues_algorithm() {
        HOTPGenerator generator = HOTPGenerator.Builder.withDefaultValues(secret.getBytes());
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void builderDefaultValues_passwordLength() {
        HOTPGenerator generator = HOTPGenerator.Builder.withDefaultValues(secret.getBytes());
        int expected = 6;

        assertThat(generator.getPasswordLength(), is(expected));
    }

    @Test
    void getURIWithIssuer_doesNotThrow() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();

        assertDoesNotThrow(() -> {
           generator.getURI(10, "issuer");
        });
    }

    @Test
    void getURIWithIssuer() throws URISyntaxException {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        URI uri = generator.getURI(10, "issuer");

        assertThat( uri.toString(), is("otpauth://hotp/issuer?digits=6&counter=10&secret=" + secret + "&algorithm=SHA1"));
    }

    @Test
    void getURIWithIssuerAndAccount_doesNotThrow() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();

        assertDoesNotThrow(() -> {
            generator.getURI(100, "issuer", "account");
        });
    }

    @Test
    void getURIWithIssuerAndAccount() throws URISyntaxException {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();

        URI uri = generator.getURI(100, "issuer", "account");
        assertThat(uri.toString(), is("otpauth://hotp/issuer:account?digits=6&counter=100&secret=" + secret + "&algorithm=SHA1"));
    }

    @Test
    void fromURIWithAlgorithmUppercase() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?counter=10&algorithm=SHA256&secret=" + secret);

        HOTPGenerator generator = HOTPGenerator.Builder.fromURI(uri);
        HMACAlgorithm expected = HMACAlgorithm.SHA256;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void fromURIWithAlgorithmLowercase() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?counter=10&algorithm=sha256&secret=" + secret);
        HOTPGenerator generator = HOTPGenerator.Builder.fromURI(uri);
        HMACAlgorithm expected = HMACAlgorithm.SHA256;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void fromURIWithDigitsIs7() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?digits=7&counter=10&secret=" + secret);
        HOTPGenerator generator = HOTPGenerator.Builder.fromURI(uri);
        int expected = 7;

        assertThat(generator.getPasswordLength(), is(expected));
    }

    @Test
    void fromURIWithInvalidDigits_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?digits=invalid&counter=10&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> HOTPGenerator.Builder.fromURI(uri));
    }

    @Test
    void fromURIWithInvalidAlgorithm_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?counter=10&algorithm=invalid&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> HOTPGenerator.Builder.fromURI(uri));
    }

    @Test
    void fromURIWithInvalidSecret_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?counter=10");

        assertThrows(IllegalArgumentException.class, () -> HOTPGenerator.Builder.fromURI(uri));
    }
}