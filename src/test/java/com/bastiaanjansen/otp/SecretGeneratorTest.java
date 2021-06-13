package com.bastiaanjansen.otp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecretGeneratorTest {

    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void generate() {
        assertEquals(32, SecretGenerator.generate().length);
        assertEquals(56, SecretGenerator.generate(256).length);
    }
}