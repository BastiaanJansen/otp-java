package com.bastiaanjansen.otp;

import com.bastiaanjansen.otp.helpers.URIHelper;

import java.io.UnsupportedEncodingException;
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
public class TOTPGenerator extends OTPGenerator {
    private final static String OTP_TYPE = "totp";

    /**
     * Time interval between new codes
     */
    private final Duration period;

    /**
     * Constructs generator with custom password length, time interval and hashing algorithm
     *
     * @param passwordLength number of digits for generated code in range 6...8
     * @param period time interval between new codes
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret used to generate hash
     */
    public TOTPGenerator(final int passwordLength, final Duration period, final HMACAlgorithm algorithm, final byte[] secret) {
        super(passwordLength, algorithm, secret);
        this.period = period;
    }

    /**
     * Generate a time-based one-time password for current time interval instant
     *
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    public String generate() throws IllegalStateException {
        long counter = calculateCounter(period);
        return super.generateCode(counter);
    }

    /**
     * Generate a time-based one-time password for a Java instant
     *
     * @param instant an instant
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    public String generate(final Instant instant) throws IllegalStateException {
        return generate(instant.toEpochMilli());
    }

    /**
     * Generate a time-based one-time password for a specific date
     *
     * @param date specific date
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    public String generate(final Date date) throws IllegalStateException {
        long secondsSince1970 = TimeUnit.MILLISECONDS.toSeconds(date.getTime());
        return generate(secondsSince1970);
    }

    /**
     * Generate a time-based one-time password for a specific time based on seconds past 1970
     *
     * @param secondsPast1970 seconds past 1970
     * @return generated TOTP code
     * @throws IllegalArgumentException when code could not be generated
     */
    public String generate(final long secondsPast1970) throws IllegalArgumentException {
        if (!validateTime(secondsPast1970)) {
            throw new IllegalArgumentException("Time must be above zero");
        }
        long counter = calculateCounter(secondsPast1970, period);
        return super.generateCode(counter);
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
     * Create a OTPAuth URI for easy onboarding with only an issuer
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
        query.put("period", String.valueOf(period.getSeconds()));

        String path = account.isEmpty() ? issuer : String.format("%s:%s", issuer, account);

        return getURI(OTP_TYPE, path, query);
    }

    /**
     * Calculate counter for a specific time in seconds past 1970 and time interval
     *
     * @param secondsPast1970 seconds past 1970
     * @param period time interval between new codes
     * @return counter based on seconds past 1970 and time interval
     */
    private long calculateCounter(final long secondsPast1970, final Duration period) {
        return TimeUnit.SECONDS.toMillis(secondsPast1970) / TimeUnit.SECONDS.toMillis(period.getSeconds());
    }

    /**
     * Calculate counter based on current time and a specific time interval
     *
     * @param period time interval between new codes
     * @return counter based on current time and a specific time interval
     */
    private long calculateCounter(final Duration period) {
        return System.currentTimeMillis() / TimeUnit.SECONDS.toMillis(period.getSeconds());
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
    public static class Builder extends OTPGenerator.Builder<Builder, TOTPGenerator>  {
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
        public Builder getBuilder() {
            return this;
        }

        /**
         * Build a TOTPGenerator from an OTPAuth URI
         *
         * @param uri OTPAuth URI
         * @return TOTPGenerator
         * @throws UnsupportedEncodingException when URI cannot be decoded
         */
        public static TOTPGenerator fromOTPAuthURI(final URI uri) throws UnsupportedEncodingException {
            Map<String, String> query = URIHelper.queryItems(uri);

            String secret = Optional.ofNullable(query.get("secret"))
                    .orElseThrow(() -> new IllegalArgumentException("Secret query parameter must be set"));

            TOTPGenerator.Builder builder = new TOTPGenerator.Builder(secret.getBytes());

            Optional.ofNullable(query.get("digits")).map(Integer::valueOf)
                    .ifPresent(builder::withPasswordLength);
            Optional.ofNullable(query.get("algorithm")).map(HMACAlgorithm::valueOf)
                    .ifPresent(builder::withAlgorithm);
            Optional.ofNullable(query.get("period")).map(Long::parseLong).map(Duration::ofSeconds)
                    .ifPresent(builder::withPeriod);

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
    }
}
