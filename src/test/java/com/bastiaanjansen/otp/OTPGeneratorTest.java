package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

class OTPGeneratorTest {

    private final byte[] secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q".getBytes();

    @Test
    void generateWithSHA1() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret);
        assertEquals("560287", generator.generateCode(1));
    }

    @Test
    void generateWithSHA256() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA256, secret);
        assertEquals("361406", generator.generateCode(1));
    }

    @Test
    void generateWithSHA512() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA512, secret);
        assertEquals("016738", generator.generateCode(1));
    }

    @Test
    void verifyCode() {
        OTPGenerator generator = new OTPGenerator(6, HMACAlgorithm.SHA1, secret);
        String code = generator.generateCode(10);
        assertTrue(generator.verify(code, 10));
        assertFalse(generator.verify(code, 9));
        assertTrue(generator.verify(code, 9, 1));
        assertTrue(generator.verify(code, 11, 1));
        assertTrue(generator.verify(code, 8, 2));
        assertFalse(generator.verify(code, 20, 2));
    }
}