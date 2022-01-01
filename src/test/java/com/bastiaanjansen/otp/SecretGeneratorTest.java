package com.bastiaanjansen.otp;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecretGeneratorTest {

    @Test
    void generate_defaultLengthIs32() {
        int expected = 32;
        assertThat(SecretGenerator.generate().length, is(expected));
    }

    @Test
    void generate_lengthIs56() {
        int expected = 56;
        assertThat(SecretGenerator.generate(256).length, is(expected));
    }

    @Test
    void generateWithZeroBits_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> SecretGenerator.generate(0));
    }

    @Test
    void generateWithLessThanZeroBits_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> SecretGenerator.generate(-1));
    }
}