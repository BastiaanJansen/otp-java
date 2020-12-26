import helpers.URIHelper;
import interfaces.ITOTPGenerator;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Generates time-based one-time passwords
 * @author Bastiaan Jansen
 */
public class TOTPGenerator extends OneTimePasswordGenerator implements ITOTPGenerator {
    /**
     * Time interval between new codes
     */
    private final Duration period;

    /**
     * Default time interval for a time-based one-time password
     */
    public static final Duration DEFAULT_TIME_INTERVAL = Duration.ofSeconds(30);

    /**
     * Constructs generator
     * @param secret used to generate hash
     */
    public TOTPGenerator(final String secret) {
        this(DEFAULT_TIME_INTERVAL, secret);
    }

    /**
     * Constructs generator with custom password length
     * @param passwordLength number of digits for generated code in range 6...8
     * @param secret used to generate hash
     */
    public TOTPGenerator(final int passwordLength, final String secret) {
        super(passwordLength, secret);
        this.period = DEFAULT_TIME_INTERVAL;
    }

    /**
     * Constructs generator with custom time interval
     * @param period time interval between new codes
     * @param secret used to generate hash
     */
    public TOTPGenerator(final Duration period, final String secret) {
        super(secret);
        this.period = period;
    }

    /**
     * Constructs generator with custom time interval and hashing algorithm
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
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret used to generate hash
     */
    public TOTPGenerator(final HMACAlgorithm algorithm, final String secret) {
        super(algorithm, secret);
        this.period = DEFAULT_TIME_INTERVAL;
    }

    /**
     * Constructs generator with custom password length and time interval
     * @param passwordLength number of digits for generated code in range 6...8
     * @param period time interval between new codes
     * @param secret used to generate hash
     */
    public TOTPGenerator(final int passwordLength, final Duration period, final String secret) {
        super(passwordLength, secret);
        this.period = period;
    }

    /**
     * Constructs generator with custom password length, time interval and hashing algorithm
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
     * @param uri OTPAuth URI
     * @throws UnsupportedEncodingException when URI query can't be encoded
     */
    public TOTPGenerator(URI uri) throws UnsupportedEncodingException {
        super(uri);
        Map<String, String> query = URIHelper.queryItems(uri);
        String period = query.get("period");

        if (period == null) throw new IllegalArgumentException("Period query parameter must be set");

        this.period = Duration.ofSeconds(Integer.valueOf(period));
    }

    /**
     * Generate a time-based one-time password for current time interval instant
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    @Override
    public String generate() throws IllegalStateException {
        long counter = calculateCounter(period);
        return super.generate(counter);
    }

    /**
     * Generate a time-based one-time password for a Java instant
     * @param instant an instant
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    @Override
    public String generate(Instant instant) throws IllegalStateException {
        return generate(instant.toEpochMilli());
    }

    /**
     * Generate a time-based one-time password for a specific date
     * @param date specific date
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    @Override
    public String generate(Date date) throws IllegalStateException {
        long timeSince1970 = date.getTime();
        return generate(timeSince1970);
    }

    /**
     * Generate a time-based one-time password for a specific time based on seconds past 1970
     * @param secondsPast1970 seconds past 1970
     * @return generated TOTP code
     * @throws IllegalArgumentException when code could not be generated
     */
    @Override
    public String generate(long secondsPast1970) throws IllegalArgumentException {
        if (!validateTime(secondsPast1970)) {
            throw new IllegalArgumentException("Time must be above zero");
        }
        long counter = calculateCounter(secondsPast1970, period);
        return super.generate(counter);
    }

    /**
     * Checks wheter a code is valid for a specific counter
     * @param code an OTP code
     * @return a boolean, true if code is valid, otherwise false
     */
    @Override
    public boolean verify(String code) {
        long counter = calculateCounter(period);
        return super.verify(code, counter);
    }

    @Override
    public Duration getPeriod() {
        return period;
    }

    /**
     * Calculate the counter for a specific date
     * @param date specific date
     * @param period time interval between new codes
     * @return counter based on a specific date and time interval
     */
    private long calculateCounter(Date date, Duration period) {
        return calculateCounter(date.getTime(), period);
    }

    /**
     * Calculate counter for a specific time in seconds past 1970 and time interval
     * @param secondsPast1970 seconds past 1970
     * @param period time interval between new codes
     * @return counter based on seconds past 1970 and time interval
     */
    private long calculateCounter(long secondsPast1970, Duration period) {
        return TimeUnit.SECONDS.toMillis(secondsPast1970) / TimeUnit.SECONDS.toMillis(period.getSeconds());
    }

    /**
     * Calculate counter based on current time and a specific time interval
     * @param period time interval between new codes
     * @return counter based on current time and a specific time interval
     */
    private long calculateCounter(Duration period) {
        return System.currentTimeMillis() / TimeUnit.SECONDS.toMillis(period.getSeconds());
    }

    /**
     * Check if time is above zero
     * @param time time value to check against
     * @return whether time is above zero
     */
    private boolean validateTime(long time) {
        return time > 0;
    }
}
