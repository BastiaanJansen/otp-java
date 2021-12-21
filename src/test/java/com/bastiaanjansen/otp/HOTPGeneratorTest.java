package com.bastiaanjansen.otp;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HOTPGeneratorTest {

    private final String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    @Test
    void generateWithSixDigits() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        int expected = 6;

        assertThat(generator.generate(1).length(), is(expected));
    }

    @Test
    void generateWithSevenDigits() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).withPasswordLength(7).build();
        int expected = 7;

        assertThat(generator.generate(1).length(), is(expected));
    }

    @Test
    void generateWithEightDigits() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).withPasswordLength(8).build();
        int expected = 8;

        assertThat(generator.generate(1).length(), is(expected));
    }

    @Test
    void generateWithCounter1() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        String expected = "560287";

        assertThat(generator.generate(1), is(expected));
    }

    @Test
    void generateWithCounter100() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        String expected = "239543";

        assertThat(generator.generate(100), is(expected));
    }

    @Test
    void generateWithCounter0() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        String expected = "455216";

        assertThat(generator.generate(0), is(expected));
    }

    @Test
    void generateWithNegativeCounter_throwsIllegalArgumentException() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();

        assertThrows(IllegalArgumentException.class, () -> generator.generate(-1));
    }

    @Test
    void verifyCurrentCode_true() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        String code = generator.generate(1);

        assertThat(generator.verify(code, 1), is(true));
    }

    @Test
    void verifyOlderCodeWithDelayWindowIs0_false() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        String code = generator.generate(1);

        assertThat(generator.verify(code, 2), is(false));
    }

    @Test
    void verifyOlderCodeWithDelayWindowIs1_true() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        String code = generator.generate(1);

        assertThat(generator.verify(code, 2, 1), is(true));
    }

    @Test
    void withDefaultValues_algorithm() {
        HOTPGenerator generator = HOTPGenerator.withDefaultValues(secret.getBytes());
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void withDefaultValues_passwordLength() {
        HOTPGenerator generator = HOTPGenerator.withDefaultValues(secret.getBytes());
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

        HOTPGenerator generator = HOTPGenerator.fromURI(uri);
        HMACAlgorithm expected = HMACAlgorithm.SHA256;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void fromURIWithAlgorithmLowercase() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?counter=10&algorithm=sha256&secret=" + secret);
        HOTPGenerator generator = HOTPGenerator.fromURI(uri);
        HMACAlgorithm expected = HMACAlgorithm.SHA256;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void fromURIWithDigitsIs7() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?digits=7&counter=10&secret=" + secret);
        HOTPGenerator generator = HOTPGenerator.fromURI(uri);
        int expected = 7;

        assertThat(generator.getPasswordLength(), is(expected));
    }

    @Test
    void fromURIWithInvalidDigits_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?digits=invalid&counter=10&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> HOTPGenerator.fromURI(uri));
    }

    @Test
    void fromURIWithInvalidAlgorithm_throwsURISyntaxException() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?counter=10&algorithm=invalid&secret=" + secret);

        assertThrows(URISyntaxException.class, () -> HOTPGenerator.fromURI(uri));
    }

    @Test
    void fromURIWithInvalidSecret_throwsIllegalArgumentException() throws URISyntaxException {
        URI uri = new URI("otpauth://hotp/issuer?counter=10");

        assertThrows(IllegalArgumentException.class, () -> HOTPGenerator.fromURI(uri));
    }

    @Nested
    class BuilderTest {
        @Test
        void builderWithEmptySecret_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> new HOTPGenerator.Builder(new byte[]{}).build());
        }

        @Test
        void builderWithPasswordLengthIs5_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> {
                new HOTPGenerator.Builder(secret.getBytes()).withPasswordLength(5).build();
            });
        }

        @Test
        void builderWithPasswordLengthIs9_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> {
                new HOTPGenerator.Builder(secret.getBytes()).withPasswordLength(9).build();
            });
        }

        @Test
        void builderWithPasswordLengthIs6() {
            HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).withPasswordLength(6).build();
            int expected = 6;

            assertThat(generator.getPasswordLength(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA1() {
            HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).withAlgorithm(HMACAlgorithm.SHA1).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA1;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA256() {
            HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).withAlgorithm(HMACAlgorithm.SHA256).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA256;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA512() {
            HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).withAlgorithm(HMACAlgorithm.SHA512).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA512;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @Test
        void builderWithInvalidPasswordLength_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> new HOTPGenerator.Builder(secret.getBytes()).withPasswordLength(5).build());
        }

        @Test
        void builderWithoutAlgorithm_defaultAlgorithm() {
            HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA1;

            assertThat(generator.getAlgorithm(), is(expected));
        }
    }
}