package com.bastiaanjansen.otp.builders;

import com.bastiaanjansen.otp.TOTPGenerator;

import java.time.Duration;

public class TOTPGeneratorBuilder extends OneTimePasswordGeneratorBuilder<TOTPGeneratorBuilder, TOTPGenerator> {

    private Duration period;

    /**
     * Default time interval for a time-based one-time password
     */
    public static final Duration DEFAULT_PERIOD = Duration.ofSeconds(30);

    public TOTPGeneratorBuilder(byte[] secret) {
        super(secret);
        this.period = DEFAULT_PERIOD;
    }

    public void withPeriod(Duration period) {
        this.period = period;
    }

    @Override
    public TOTPGenerator create() {
        return new TOTPGenerator(passwordLength, period, algorithm, secret);
    }

    @Override
    public TOTPGeneratorBuilder getBuilder() {
        return this;
    }
}
