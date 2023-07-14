package com.bastiaanjansen.otp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class HOTPVerifierTest {

    private final static String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    private HOTPGenerator generator;
    private HOTPVerifier verifier;

    @BeforeEach
    void setUp() {
        generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        verifier = new HOTPVerifier(generator, new MemorySingleUseTokenStorageProvider());
    }

    @Test
    void verifyCurrentCode_true() {
        String code = generator.generate(1);

        assertThat(verifier.verify(code, 1), is(true));
    }

    @Test
    void verifyCurrentCodeTwice_false() {
        String code = generator.generate(1);

        verifier.verify(code, 1);

        assertThat(verifier.verify(code, 1), is(false));
    }

    @Test
    void verifyCurrentCodeTwice_withDifferentGenerators_true() {
        HOTPGenerator generator = new HOTPGenerator.Builder(secret.getBytes()).build();
        HOTPGenerator generator2 = new HOTPGenerator.Builder("vv3kouqj4kyakohmzpph3us4cf3zknb5c2oobq6msjdhgjv2kiyskduh8".getBytes()).build();

        String code = generator.generate(1);
        String code2 = generator2.generate(1);

        verifier.verify(code, 1);

        assertThat(verifier.verify(code2, 1), is(true));
    }

    @Test
    void verifyOlderCodeWithDelayWindowIs0_false() {
        String code = generator.generate(1);

        assertThat(verifier.verify(code, 2), is(false));
    }

    @Test
    void verifyOlderCodeWithDelayWindowIs1_true() {
        String code = generator.generate(1);

        assertThat(verifier.verify(code, 2, 1), is(true));
    }


}