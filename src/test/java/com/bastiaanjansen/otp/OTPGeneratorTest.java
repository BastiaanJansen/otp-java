package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OTPGeneratorTest {

    private final String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    @Test
    void constructorWithEmptySecret_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OTPGenerator(6, HMACAlgorithm.SHA1, new byte[]{}));
    }

    @Test
    void constructorWithPasswordLengthIs5_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OTPGenerator(5, HMACAlgorithm.SHA1, secret.getBytes()));
    }

    @Test
    void constructorWithPasswordLengthIs9_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OTPGenerator(9, HMACAlgorithm.SHA1, secret.getBytes()));
    }

    @Test
    void constructorWithAlgorithmSHA1() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        HMACAlgorithm expected = HMACAlgorithm.SHA1;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void constructorWithAlgorithmSHA256() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA256, secret.getBytes());
        HMACAlgorithm expected = HMACAlgorithm.SHA256;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void constructorWithAlgorithmSHA512() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA512, secret.getBytes());
        HMACAlgorithm expected = HMACAlgorithm.SHA512;

        assertThat(generator.getAlgorithm(), is(expected));
    }

    @Test
    void constructorWithPasswordLengthIs6() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        int expected = 6;

        assertThat(generator.getPasswordLength(), is(expected));
    }

    @Test
    void generateWithPasswordLengthIs6() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        int expected = 6;

        assertThat(generator.generateCode(1).length(), is(expected));
    }

    @Test
    void generateWithPasswordLengthIs7() {
        OTPGenerator generator = new OTPGenerator(7, HMACAlgorithm.SHA1, secret.getBytes());
        int expected = 7;

        assertThat(generator.generateCode(1).length(), is(expected));
    }

    @Test
    void generateWithPasswordLengthIs8() {
        OTPGenerator generator = new OTPGenerator(8, HMACAlgorithm.SHA1, secret.getBytes());
        int expected = 8;

        assertThat(generator.generateCode(1).length(), is(expected));
    }

    @Test
    void generateWithSHA1() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        String expected = "560287";

        assertThat(generator.generateCode(1), is(expected));
    }

    @Test
    void generateWithSHA256() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA256, secret.getBytes());
        String expected = "361406";

        assertThat(generator.generateCode(1), is(expected));
    }

    @Test
    void generateWithSHA512() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA512, secret.getBytes());
        String expected = "016738";

        assertThat(generator.generateCode(1), is(expected));
    }

    @Test
    void generateWithCounterIs2() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        String expected = "447843";

        assertThat(generator.generateCode(2), is(expected));
    }

    @Test
    void generateWithCounterIs100() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        String expected = "239543";

        assertThat(generator.generateCode(100), is(expected));
    }

    @Test
    void generateWithInvalidCounter_throwsIllegalArgumentException() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());

        assertThrows(IllegalArgumentException.class, () -> generator.generateCode(-1));
    }

    @Test
    void verifyWithCounterIs10AndDelayWindowIs0_true() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        String code = generator.generateCode(10);

        assertThat(generator.verify(code, 10), is(true));
    }

    @Test
    void verifyWithCounterIs9AndDelayWindowIs0_false() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        String code = generator.generateCode(10);

        assertThat(generator.verify(code, 9), is(false));
    }

    @Test
    void verifyWithCounterIs9AndDelayWindowIs1_true() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        String code = generator.generateCode(10);

        assertThat(generator.verify(code, 9, 1), is(true));
    }

    @Test
    void verifyWithCounterIs11AndDelayWindowIs1_true() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        String code = generator.generateCode(10);

        assertThat(generator.verify(code, 11, 1), is(true));
    }

    @Test
    void verifyWithCounterIs8AndDelayWindowIs2_true() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        String code = generator.generateCode(10);

        assertThat(generator.verify(code, 8, 2), is(true));
    }

    @Test
    void verifyWithCounterIs20AndDelayWindowIs2_false() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret.getBytes());
        String code = generator.generateCode(10);

        assertThat(generator.verify(code, 20, 2), is(false));
    }
}