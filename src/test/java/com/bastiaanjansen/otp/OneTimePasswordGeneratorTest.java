package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

class OneTimePasswordGeneratorTest {

    private final String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    @Test
    void generateWithSHA1() {
        OneTimePasswordGenerator generator = new OneTimePasswordGenerator(HMACAlgorithm.SHA1, secret);
        assertEquals("560287", generator.generateCode(1));
    }

    @Test
    void generateWithSHA256() {
        OneTimePasswordGenerator generator = new OneTimePasswordGenerator(HMACAlgorithm.SHA256, secret);
        assertEquals("361406", generator.generateCode(1));
    }

    @Test
    void generateWithSHA512() {
        OneTimePasswordGenerator generator = new OneTimePasswordGenerator(HMACAlgorithm.SHA512, secret);
        assertEquals("016738", generator.generateCode(1));
    }

    @Test
    void verifyCode() {
        OneTimePasswordGenerator generator = new OneTimePasswordGenerator(secret);
        String code = generator.generateCode(10);
        assertTrue(generator.verify(code, 10));
        assertFalse(generator.verify(code, 9));
        assertTrue(generator.verify(code, 9, 1));
        assertTrue(generator.verify(code, 11, 1));
        assertTrue(generator.verify(code, 8, 2));
        assertFalse(generator.verify(code, 20, 2));
    }
}