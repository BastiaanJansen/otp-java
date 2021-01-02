package com.bastiaanjansen.otp.builders;

import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.TOTPGenerator;
import com.bastiaanjansen.otp.helpers.URIHelper;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * @author Bastiaan Jansen
 * @see OTPBuilder
 * @see TOTPGenerator
 */
public class TOTPGeneratorBuilder extends OTPBuilder<TOTPGeneratorBuilder, TOTPGenerator> {

    /**
     * Time interval between new codes
     */
    private Duration period;

    /**
     * Default time interval for a time-based one-time password
     */
    public static final Duration DEFAULT_PERIOD = Duration.ofSeconds(30);

    /**
     * Constructs a TOTPGenerator builder
     *
     * @param secret used to generate hash
     */
    public TOTPGeneratorBuilder(byte[] secret) {
        super(secret);
        this.period = DEFAULT_PERIOD;
    }

    /**
     * Change period
     *
     * @param period time interval between new codes
     * @return builder
     */
    public TOTPGeneratorBuilder withPeriod(Duration period) {
        this.period = period;
        return this;
    }

    public Duration getPeriod() {
        return period;
    }

    /**
     * Build the generator with specified options
     *
     * @return TOTPGenerator
     */
    @Override
    public TOTPGenerator build() {
        return new TOTPGenerator(passwordLength, period, algorithm, secret);
    }

    @Override
    public TOTPGeneratorBuilder getBuilder() {
        return this;
    }

    /**
     * Build a TOTPGenerator from an OTPAuth URI
     *
     * @param uri OTPAuth URI
     * @return TOTPGenerator
     * @throws UnsupportedEncodingException when URI cannot be decoded
     */
    public static TOTPGenerator withOTPAuthURI(final URI uri) throws UnsupportedEncodingException {
        Map<String, String> query = URIHelper.queryItems(uri);

        String secret = query.get("secret");
        if (secret == null) throw new IllegalArgumentException("Secret query parameter must be set");

        TOTPGeneratorBuilder builder = new TOTPGeneratorBuilder(secret.getBytes());

        if (query.containsKey("digits")) {
            int passwordLength = Integer.parseInt(query.get("digits"));
            builder.withPasswordLength(passwordLength);
        }

        if (query.containsKey("algorithm")) {
            HMACAlgorithm algorithm = HMACAlgorithm.valueOf(query.get("algorithm"));
            builder.withAlgorithm(algorithm);
        }

        if (query.containsKey("period")) {
            Duration period = Duration.ofSeconds(Long.parseLong(query.get("period")));
            builder.withPeriod(period);
        }

        return builder.build();
    }
}
