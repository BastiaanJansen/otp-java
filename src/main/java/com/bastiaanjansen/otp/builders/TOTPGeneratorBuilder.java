package com.bastiaanjansen.otp.builders;

import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.TOTPGenerator;
import com.bastiaanjansen.otp.helpers.URIHelper;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;

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

    @Override
    public TOTPGeneratorBuilder withOTPAuthURI(final URI uri) throws UnsupportedEncodingException {
        super.withOTPAuthURI(uri);
        Map<String, String> query = URIHelper.queryItems(uri);
        this.period = Duration.ofSeconds(Integer.parseInt(query.getOrDefault("period", String.valueOf(DEFAULT_PERIOD.getSeconds()))));
        return this;
    }

    public void withPeriod(Duration period) {
        this.period = period;
    }

    public Duration getPeriod() {
        return period;
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
