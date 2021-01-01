package com.bastiaanjansen.otp;

import com.bastiaanjansen.otp.helpers.URIHelper;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Generates time-based one-time passwords
 *
 * @author Bastiaan Jansen
 * @see OneTimePasswordGenerator
 */
public class TOTPGenerator extends OneTimePasswordGenerator {
    /**
     * Time interval between new codes
     */
    private final Duration period;

    /**
     * Default time interval for a time-based one-time password
     */
    public static final Duration DEFAULT_PERIOD = Duration.ofSeconds(30);

    /**
     * Constructs generator
     *
     * @param secret used to generate hash
     */
    public TOTPGenerator(final String secret) {
        this(DEFAULT_PERIOD, secret);
    }

    /**
     * Constructs generator with custom password length
     *
     * @param passwordLength number of digits for generated code in range 6...8
     * @param secret used to generate hash
     */
    public TOTPGenerator(final int passwordLength, final String secret) {
        super(passwordLength, secret);
        this.period = DEFAULT_PERIOD;
    }

    /**
     * Constructs generator with custom time interval
     *
     * @param period time interval between new codes
     * @param secret used to generate hash
     */
    public TOTPGenerator(final Duration period, final String secret) {
        super(secret);
        this.period = period;
    }

    /**
     * Constructs generator with custom time interval and hashing algorithm
     *
     * @param period time interval between new codes
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret used to generate hash
     */
    public TOTPGenerator(final Duration period, HMACAlgorithm algorithm, final String secret) {
        super(algorithm, secret);
        this.period = period;
    }

    /**
     * Constructs generator with custom hashing algorithm and default time interval
     *
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret used to generate hash
     */
    public TOTPGenerator(final HMACAlgorithm algorithm, final String secret) {
        super(algorithm, secret);
        this.period = DEFAULT_PERIOD;
    }

    /**
     * Constructs generator with custom password length and period
     *
     * @param passwordLength number of digits for generated code in range 6...8
     * @param period time interval between new codes
     * @param secret used to generate hash
     */
    public TOTPGenerator(final int passwordLength, final Duration period, final String secret) {
        super(passwordLength, secret);
        this.period = period;
    }

    /**
     * Constructs generator with custom password length and hashing algorithm
     *
     * @param passwordLength number of digits for generated code in range 6...8
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret used to generate hash
     */
    public TOTPGenerator(final int passwordLength, final HMACAlgorithm algorithm, final String secret) {
        super(passwordLength, algorithm, secret);
        this.period = DEFAULT_PERIOD;
    }

    /**
     * Constructs generator with custom password length, time interval and hashing algorithm
     *
     * @param passwordLength number of digits for generated code in range 6...8
     * @param period time interval between new codes
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret used to generate hash
     */
    public TOTPGenerator(final int passwordLength, final Duration period, final HMACAlgorithm algorithm, final String secret) {
        super(passwordLength, algorithm, secret);
        this.period = period;
    }

    /**
     * Constructs generator from a OTPAuth URI
     *
     * @param uri OTPAuth URI
     * @throws UnsupportedEncodingException when URI query can't be encoded
     */
    public TOTPGenerator(final URI uri) throws UnsupportedEncodingException {
        super(uri);
        Map<String, String> query = URIHelper.queryItems(uri);
        int period = Integer.parseInt(query.getOrDefault("period", String.valueOf(DEFAULT_PERIOD.getSeconds())));

        this.period = Duration.ofSeconds(period);
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
        return generateCode(instant.toEpochMilli());
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
        return generateCode(secondsSince1970);
    }

    /**
     * Generate a time-based one-time password for a specific time based on seconds past 1970
     *
     * @param secondsPast1970 seconds past 1970
     * @return generated TOTP code
     * @throws IllegalArgumentException when code could not be generated
     */
    public String generateCode(final long secondsPast1970) throws IllegalArgumentException {
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
        query.put("digits", String.valueOf(passwordLength));
        query.put("algorithm", algorithm.name());
        query.put("secret", secret);

        String path = account.isEmpty() ? issuer : String.format("%s:%s", issuer, account);

        return getURI("totp", path, query);
    }

    /**
     * Calculate the counter for a specific date
     *
     * @param date specific date
     * @param period time interval between new codes
     * @return counter based on a specific date and time interval
     */
    private long calculateCounter(final Date date, final Duration period) {
        return calculateCounter(date.getTime(), period);
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
}
