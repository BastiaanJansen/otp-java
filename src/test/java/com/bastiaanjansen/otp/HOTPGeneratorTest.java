package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HOTPGeneratorTest {

    private final byte[] secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q".getBytes();

    @Test
    void generateWithSixDigits() {
        HOTPGenerator generator = new HOTPGenerator(6, HMACAlgorithm.SHA1, secret);
        assertEquals("560287", generator.generateCode(1));
    }

    @Test
    void generateWithSevenDigits() {
        HOTPGenerator generator = new HOTPGenerator(7, HMACAlgorithm.SHA1, secret);
        assertEquals("1560287", generator.generateCode(1));
    }

    @Test
    void generateWithEightDigits() {
        HOTPGenerator generator = new HOTPGenerator(8, HMACAlgorithm.SHA1, secret);
        assertEquals("61560287", generator.generateCode(1));
    }

    @Test
    void builderDefaultValues() {
        HOTPGenerator generator = HOTPGenerator.Builder.withDefaultValues(secret);
        assertEquals(HMACAlgorithm.SHA1, generator.getAlgorithm());
        assertEquals(6, generator.getPasswordLength());
    }

    @Test
    void getURIWithIssuer() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret)
                .withAlgorithm(HMACAlgorithm.SHA1)
                .withPasswordLength(8)
                .build();

        assertDoesNotThrow(() -> {
            URI uri = generator.getURI(10, "issuer");
            assertEquals("otpauth://hotp/issuer?digits=8&counter=10&secret=vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q&algorithm=SHA1", uri.toString());
        });
    }

    @Test
    void getURIWithIssuerAndAccount() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret)
                .withAlgorithm(HMACAlgorithm.SHA256)
                .withPasswordLength(6)
                .build();

        assertDoesNotThrow(() -> {
            URI uri = generator.getURI(100, "issuer", "account");
            assertEquals("otpauth://hotp/issuer:account?digits=6&counter=100&secret=vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q&algorithm=SHA256", uri.toString());
        });
    }

    @Test
    void fromURI() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?digits=8&counter=10&secret=vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q&algorithm=SHA256");

        assertDoesNotThrow(() -> {
            HOTPGenerator generator = HOTPGenerator.Builder.fromOTPAuthURI(uri);
            assertEquals(HMACAlgorithm.SHA256, generator.getAlgorithm());
            assertEquals(8, generator.getPasswordLength());
        });
    }

    @Test
    void fromURIThrowsWhenSecretNotProvided() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?digits=8&counter=10&algorithm=SHA256");

        assertThrows(IllegalArgumentException.class, () -> {
            HOTPGenerator.Builder.fromOTPAuthURI(uri);
        });
    }

    @Test
    void fromURIThrows() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?digits=sd&counter=10&secret=vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q&algorithm=SHA256");

        assertThrows(URISyntaxException.class, () -> {
            HOTPGenerator.Builder.fromOTPAuthURI(uri);
        });
    }
}