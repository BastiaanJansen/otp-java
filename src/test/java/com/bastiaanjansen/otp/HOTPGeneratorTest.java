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
import java.util.stream.Stream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HOTPGeneratorTest {

    private final String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    private static Stream<Arguments> testData() {
        return Stream.of(
                Arguments.of(6, 1, HMACAlgorithm.SHA1, "560287"),
                Arguments.of(7, 1, HMACAlgorithm.SHA1, "1560287"),
                Arguments.of(8, 1, HMACAlgorithm.SHA1, "61560287"),

                Arguments.of(6, 1000, HMACAlgorithm.SHA1, "401796"),
                Arguments.of(6, 923892, HMACAlgorithm.SHA1, "793394"),
                Arguments.of(6, 82764924, HMACAlgorithm.SHA1, "022826"),

                Arguments.of(6, 1, HMACAlgorithm.SHA256, "361406"),
                Arguments.of(6, 1, HMACAlgorithm.SHA512, "016738"),
                Arguments.of(6, 1, HMACAlgorithm.SHA224, "422784"),
                Arguments.of(6, 1, HMACAlgorithm.SHA384, "466320")
        );
    }

    @ParameterizedTest
    @MethodSource("testData")
    void generateWithCounter(int passwordLength, long counter, HMACAlgorithm algorithm, String otp) {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret)
                .withPasswordLength(passwordLength)
                .withAlgorithm(algorithm)
                .build();

        assertThat(generator.generate(counter), is(otp));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, -100})
    void generateWithInvalidCounter_throwsIllegalArgumentException(long counter) {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();

        assertThrows(IllegalArgumentException.class, () -> generator.generate(counter));
    }

    @Test
    void verifyCurrentCode_true() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();
        String code = generator.generate(1);

        assertThat(generator.verify(code, 1), is(true));
    }

    @Test
    void verifyOlderCodeWithDelayWindowIs0_false() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();
        String code = generator.generate(1);

        assertThat(generator.verify(code, 2), is(false));
    }

    @Test
    void verifyOlderCodeWithDelayWindowIs1_true() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();
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
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();

        assertDoesNotThrow(() -> {
           generator.getURI(10, "issuer");
        });
    }

    @Test
    void getURIWithIssuerWithSpace_doesNotThrow() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();

        assertDoesNotThrow(() -> generator.getURI(10, "issuer with space"));
    }

    @Test
    void getURIWithIssuerWithSpace_doesEscapeIssuer() throws URISyntaxException {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();

        String url = generator.getURI(10, "issuer with space").toString();

        assertThat(url, is("otpauth://hotp/issuer+with+space?digits=6&counter=10&secret=vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q&issuer=issuer+with+space&algorithm=SHA1"));
    }

    @Test
    void getURIWithIssuer() throws URISyntaxException {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();
        URI uri = generator.getURI(10, "issuer");

        assertThat(uri.toString(), is("otpauth://hotp/issuer?digits=6&counter=10&secret=" + secret + "&issuer=issuer&algorithm=SHA1"));
    }

    @Test
    void getURIWithIssuerWithUrlUnsafeCharacters() throws URISyntaxException {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();
        URI uri = generator.getURI(10, "mac&cheese");

        assertThat(uri.toString(), is("otpauth://hotp/mac%26cheese?digits=6&counter=10&secret=" + secret + "&issuer=mac%26cheese&algorithm=SHA1"));
    }


    @Test
    void getURIWithIssuerAndAccount_doesNotThrow() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();

        assertDoesNotThrow(() -> {
            generator.getURI(100, "issuer", "account");
        });
    }

    @Test
    void getURIWithIssuerAndAccount() throws URISyntaxException {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();

        URI uri = generator.getURI(100, "issuer", "account");
        assertThat(uri.toString(), is("otpauth://hotp/issuer:account?digits=6&counter=100&secret=" + secret + "&issuer=issuer&algorithm=SHA1"));
    }

    @Test
    void getURIWithIssuerAndAccountWithUrlUnsafeCharacters() throws URISyntaxException {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();

        URI uri = generator.getURI(100, "mac&cheese", "ac@cou.nt");

        assertThat(uri.toString(), is("otpauth://hotp/mac%26cheese:ac%40cou.nt?digits=6&counter=100&secret=" + secret + "&issuer=mac%26cheese&algorithm=SHA1"));
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
                new HOTPGenerator.Builder(secret).withPasswordLength(5).build();
            });
        }

        @Test
        void builderWithPasswordLengthIs9_throwsIllegalArgumentException() {
            assertThrows(IllegalArgumentException.class, () -> {
                new HOTPGenerator.Builder(secret).withPasswordLength(9).build();
            });
        }

        @Test
        void builderWithPasswordLengthIs6() {
            HOTPGenerator generator = new HOTPGenerator.Builder(secret).withPasswordLength(6).build();
            int expected = 6;

            assertThat(generator.getPasswordLength(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA1() {
            HOTPGenerator generator = new HOTPGenerator.Builder(secret).withAlgorithm(HMACAlgorithm.SHA1).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA1;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA256() {
            HOTPGenerator generator = new HOTPGenerator.Builder(secret).withAlgorithm(HMACAlgorithm.SHA256).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA256;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @Test
        void builderWithAlgorithmSHA512() {
            HOTPGenerator generator = new HOTPGenerator.Builder(secret).withAlgorithm(HMACAlgorithm.SHA512).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA512;

            assertThat(generator.getAlgorithm(), Matchers.is(expected));
        }

        @ParameterizedTest
        @ValueSource(ints = { 1, 2, 3, 4, 5, 9, 10 })
        void builderWithInvalidPasswordLength_throwsIllegalArgumentException(int passwordLength) {
            assertThrows(IllegalArgumentException.class, () -> new HOTPGenerator.Builder(secret).withPasswordLength(passwordLength).build());
        }

        @Test
        void builderWithoutAlgorithm_defaultAlgorithm() {
            HOTPGenerator generator = new HOTPGenerator.Builder(secret).build();
            HMACAlgorithm expected = HMACAlgorithm.SHA1;

            assertThat(generator.getAlgorithm(), is(expected));
        }
    }
}
