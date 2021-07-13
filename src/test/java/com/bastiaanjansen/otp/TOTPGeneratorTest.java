package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import static org.junit.jupiter.api.Assertions.*;

class TOTPGeneratorTest {

    private final byte[] secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q".getBytes();

    @Test
    void generateBasedOnSecondsPast1970() {
        TOTPGenerator generator = new TOTPGenerator(6, Duration.ofSeconds(60), HMACAlgorithm.SHA1, secret);
        assertEquals("455216", generator.generate(1));
    }

    @Test
    void generateWithEightDigits() {
        TOTPGenerator generator = new TOTPGenerator(8, Duration.ofSeconds(30), HMACAlgorithm.SHA1, secret);
        assertEquals("17455216", generator.generate(1));
    }

    @Test
    void generateWithInstant() {
        TOTPGenerator generator = new TOTPGenerator(6, Duration.ofSeconds(30), HMACAlgorithm.SHA1, secret);
        assertEquals("455216", generator.generate(Instant.ofEpochMilli(1)));
    }

    @Test
    void generateWithDate() {
        TOTPGenerator generator = new TOTPGenerator(6, Duration.ofSeconds(30), HMACAlgorithm.SHA1, secret);
        Date date = new GregorianCalendar(2014, Calendar.FEBRUARY, 11).getTime();
        assertEquals("019287", generator.generate(date));
    }

    @Test
    void generateWithCustomTimeInterval() {
        TOTPGenerator generator = new TOTPGenerator(6, Duration.ofSeconds(60), HMACAlgorithm.SHA1, secret);
        assertEquals("455216", generator.generate(1));
    }

    @Test
    void builderDefaultValues() {
        TOTPGenerator generator = TOTPGenerator.Builder.withDefaultValues(secret);
        assertEquals(Duration.ofSeconds(30), generator.getPeriod());
        assertEquals(HMACAlgorithm.SHA1, generator.getAlgorithm());
        assertEquals(6, generator.getPasswordLength());
    }

    @Test
    void getURIWithIssuer() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret)
                .withAlgorithm(HMACAlgorithm.SHA1)
                .withPasswordLength(8)
                .withPeriod(Duration.ofSeconds(30))
                .build();

        assertDoesNotThrow(() -> {
            URI uri = generator.getURI("issuer");
            assertEquals("otpauth://totp/issuer?period=30&digits=8&secret=vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q&algorithm=SHA1", uri.toString());
        });
    }

    @Test
    void getURIWithIssuerAndAccount() {
        TOTPGenerator generator = new TOTPGenerator.Builder(secret)
                .withAlgorithm(HMACAlgorithm.SHA256)
                .withPasswordLength(6)
                .withPeriod(Duration.ofSeconds(60))
                .build();

        assertDoesNotThrow(() -> {
            URI uri = generator.getURI("issuer", "account");
            assertEquals("otpauth://totp/issuer:account?period=60&digits=6&secret=vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q&algorithm=SHA256", uri.toString());
        });
    }

    @Test
    void fromURI() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?period=60&digits=8&secret=vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q&algorithm=SHA256");

        assertDoesNotThrow(() -> {
            TOTPGenerator generator = TOTPGenerator.Builder.fromOTPAuthURI(uri);
            assertEquals(HMACAlgorithm.SHA256, generator.getAlgorithm());
            assertEquals(8, generator.getPasswordLength());
            assertEquals(Duration.ofSeconds(60), generator.getPeriod());
        });
    }

    @Test
    void fromURIThrows() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?period=sdsd&digits=sd&secret=vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q&algorithm=SHA256");

        assertThrows(URISyntaxException.class, () -> {
            TOTPGenerator.Builder.fromOTPAuthURI(uri);
        });
    }
}