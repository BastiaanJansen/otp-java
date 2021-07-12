package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

class HOTPGeneratorTest {

    private final byte[] secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q".getBytes();

    @Test
    void generateWithSixDigits() {
        HOTPGenerator generator = new HOTPGenerator(6, secret);
        assertEquals("560287", generator.generateCode(1));
    }

    @Test
    void generateWithSevenDigits() {
        HOTPGenerator generator = new HOTPGenerator(7, secret);
        assertEquals("1560287", generator.generateCode(1));
    }

    @Test
    void generateWithEightDigits() {
        HOTPGenerator generator = new HOTPGenerator(8, secret);
        assertEquals("61560287", generator.generateCode(1));
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
            assertEquals("otpauth://hotp/issuer:account?digits=6&counter=100&secret=vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q&algorithm=SHA1", uri.toString());
        });
    }
}