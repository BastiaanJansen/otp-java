package com.bastiaanjansen.otp;

import com.bastiaanjansen.otp.helpers.URIHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Generates time-based one-time passwords
 *
 * @author Bastiaan Jansen
 * @see OTPGenerator
 */
public final class TOTPGenerator extends OTPGenerator {
    private final static String OTP_TYPE = "totp";

    /**
     * Default time interval for a time-based one-time password
     */
    private static final Duration DEFAULT_PERIOD = Duration.ofSeconds(30);

    /**
     * Time interval between new codes
     */
    private final Duration period;

    private TOTPGenerator(final Builder builder) {
        super(builder);
        this.period = builder.period;
    }

    /**
     * Build a TOTPGenerator from an OTPAuth URI
     *
     * @param uri OTPAuth URI
     * @return TOTPGenerator
     * @throws URISyntaxException when URI cannot be parsed
     */
    public static TOTPGenerator fromURI(URI uri) throws URISyntaxException {
        Map<String, String> query = URIHelper.queryItems(uri);

        byte[] secret = Optional.ofNullable(query.get(URIHelper.SECRET))
                .map(String::getBytes)
                .orElseThrow(() -> new IllegalArgumentException("Secret query parameter must be set"));

        Builder builder = new Builder(secret);

        try {
            Optional.ofNullable(query.get(URIHelper.PERIOD))
                    .map(Long::parseLong)
                    .map(Duration::ofSeconds)
                    .ifPresent(builder::withPeriod);
            Optional.ofNullable(query.get(URIHelper.DIGITS))
                    .map(Integer::valueOf)
                    .ifPresent(builder::withPasswordLength);
            Optional.ofNullable(query.get(URIHelper.ALGORITHM))
                    .map(String::toUpperCase)
                    .map(HMACAlgorithm::valueOf)
                    .ifPresent(builder::withAlgorithm);
        } catch (Exception e) {
            throw new URISyntaxException(uri.toString(), "URI could not be parsed");
        }

        return builder.build();
    }

    /**
     * Create a TOTPGenerator with default values
     *
     * @param secret used to generate hash
     * @return a TOTPGenerator with default values
     */
    public static TOTPGenerator withDefaultValues(final byte[] secret) {
        return new TOTPGenerator.Builder(secret).build();
    }

    /**
     * Generate a time-based one-time password for current time interval instant
     *
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    public String now() throws IllegalStateException {
        long counter = calculateCounter(period);
        return super.generate(counter);
    }

    /**
     * Generate a time-based one-time password for a Java instant
     *
     * @param instant an instant
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    public String at(final Instant instant) throws IllegalStateException {
        return at(instant.getEpochSecond());
    }

    /**
     * Generate a time-based one-time password for a specific date
     *
     * @param date specific date
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    public String at(final Date date) throws IllegalStateException {
        long secondsSince1970 = TimeUnit.MILLISECONDS.toSeconds(date.getTime());
        return at(secondsSince1970);
    }

    /**
     * Generate a time-based one-time password for a specific time based on seconds past 1970
     *
     * @param secondsPast1970 seconds past 1970
     * @return generated TOTP code
     * @throws IllegalArgumentException when code could not be generated
     */
    public String at(final long secondsPast1970) throws IllegalArgumentException {
        if (!validateTime(secondsPast1970))
            throw new IllegalArgumentException("Time must be above zero");

        long counter = calculateCounter(secondsPast1970, period);
        return super.generate(counter);
    }

    /**
     * Checks whether a code is valid for a specific counter
     *
     * @param code an OTP code
     * @return a boolean, true if code is valid, otherwise false
     */
    public boolean verify(final String code) {
        long counter = calculateCounter(period);
        return super.verify(code, counter);
    }

    /**
     * Checks whether a code is valid for a specific counter taking a delay window into account
     *
     * @param code an OTP code
     * @param delayWindow window in which a code can still be deemed valid
     * @return a boolean, true if code is valid, otherwise false
     */
    public boolean verify(final String code, final int delayWindow) {
        long counter = calculateCounter(period);
        return super.verify(code, counter, delayWindow);
    }

    public Duration getPeriod() {
        return period;
    }

    /**
     * Create a OTPAuth URI for easy on-boarding with only an issuer
     *
     * @param issuer name
     * @return generated OTPAuth URI
     * @throws URISyntaxException when URI cannot be created
     */
    public URI getURI(final String issuer) throws URISyntaxException {
        return getURI(issuer, "");
    }

    /**
     * Create a OTPAuth URI for easy user on-boarding with an issuer and account name
     *
     * @param issuer name
     * @param account name
     * @return generated OTPAuth URI
     * @throws URISyntaxException when URI cannot be created
     */
    public URI getURI(final String issuer, final String account) throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        query.put(URIHelper.PERIOD, String.valueOf(period.getSeconds()));

        return getURI(OTP_TYPE, issuer, account, query);
    }

    /**
     * Calculate counter for a specific time in seconds past 1970 and time interval
     *
     * @param secondsPast1970 seconds past 1970
     * @param period time interval between new codes
     * @return counter based on seconds past 1970 and time interval
     */
    private long calculateCounter(final long secondsPast1970, final Duration period) {
        return TimeUnit.SECONDS.toMillis(secondsPast1970) / period.toMillis();
    }

    /**
     * Calculate counter based on current time and a specific time interval
     *
     * @param period time interval between new codes
     * @return counter based on current time and a specific time interval
     */
    private long calculateCounter(final Duration period) {
        return System.currentTimeMillis() / period.toMillis();
    }

    /**
     * Check if time is above zero
     *
     * @param time time value to check against
     * @return whether time is above zero
     */
    private boolean validateTime(final long time) {
        return time > 0;
    }


    /**
     * @author Bastiaan Jansen
     * @see TOTPGenerator
     */
    public static class Builder extends OTPGenerator.Builder<TOTPGenerator, Builder>  {
        /**
         * Time interval between new codes
         */
        private Duration period;

        /**
         * Constructs a TOTPGenerator builder
         *
         * @param secret used to generate hash
         */
        public Builder(byte[] secret) {
            super(secret);
            this.period = DEFAULT_PERIOD;
        }

        /**
         * Change period
         *
         * @param period time interval between new codes
         * @return builder
         */
        public Builder withPeriod(Duration period) {
            if (period.getSeconds() < 1) throw new IllegalArgumentException("Period must be at least 1 second");
            this.period = period;
            return this;
        }

        /**
         * Build the generator with specified options
         *
         * @return TOTPGenerator
         */
        @Override
        public TOTPGenerator build() {
            return new TOTPGenerator(this);
        }

        @Override
        protected Builder getBuilder() {
            return this;
        }
    }
}
