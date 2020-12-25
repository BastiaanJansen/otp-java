import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Generates time-based one-time passwords
 * @author Bastiaan Jansen
 */
public class TOTPGenerator extends OneTimePasswordGenerator {
    /**
     * Time interval between new codes
     */
    private final Duration timeInterval;

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
        this.timeInterval = DEFAULT_TIME_INTERVAL;
    }

    /**
     * Constructs generator with custom time interval
     * @param timeInterval time interval between new codes
     * @param secret used to generate hash
     */
    public TOTPGenerator(final Duration timeInterval, final String secret) {
        super(secret);
        this.timeInterval = timeInterval;
    }

    /**
     * Constructs generator with custom time interval and hashing algorithm
     * @param timeInterval time interval between new codes
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret used to generate hash
     */
    public TOTPGenerator(final Duration timeInterval, HMACAlgorithm algorithm, final String secret) {
        super(algorithm, secret);
        this.timeInterval = timeInterval;
    }

    /**
     * Constructs generator with custom hashing algorithm and default time interval
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret used to generate hash
     */
    public TOTPGenerator(final HMACAlgorithm algorithm, final String secret) {
        super(algorithm, secret);
        this.timeInterval = DEFAULT_TIME_INTERVAL;
    }

    /**
     * Constructs generator with custom password length and time interval
     * @param passwordLength number of digits for generated code in range 6...8
     * @param timeInterval time interval between new codes
     * @param secret used to generate hash
     */
    public TOTPGenerator(final int passwordLength, final Duration timeInterval, final String secret) {
        super(passwordLength, secret);
        this.timeInterval = timeInterval;
    }

    /**
     * Constructs generator with custom password length, time interval and hashing algorithm
     * @param passwordLength number of digits for generated code in range 6...8
     * @param timeInterval time interval between new codes
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret used to generate hash
     */
    public TOTPGenerator(final int passwordLength, final Duration timeInterval, final HMACAlgorithm algorithm, final String secret) {
        super(passwordLength, algorithm, secret);
        this.timeInterval = timeInterval;
    }

    /**
     * Generate a time-based one-time password for current time interval instant
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    public String generate() throws IllegalStateException {
        long counter = calculateCounter(timeInterval);
        return super.generate(counter);
    }

    /**
     * Generate a time-based one-time password for a Java instant
     * @param instant an instant
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
    public String generate(Instant instant) throws IllegalStateException {
        return generate(instant.toEpochMilli());
    }

    /**
     * Generate a time-based one-time password for a specific date
     * @param date specific date
     * @return generated TOTP code
     * @throws IllegalStateException when code could not be generated
     */
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
    public String generate(long secondsPast1970) throws IllegalArgumentException {
        if (!validateTime(secondsPast1970)) {
            throw new IllegalArgumentException("Time must be above zero");
        }
        long counter = calculateCounter(secondsPast1970, timeInterval);
        return super.generate(counter);
    }

    public boolean verify(String code) {
        return super.verify(code, calculateCounter(new Date(), timeInterval));
    }

    /**
     * Calculate the counter for a specific date
     * @param date specific date
     * @param timeInterval time interval between new codes
     * @return counter based on a specific date and time interval
     */
    private long calculateCounter(Date date, Duration timeInterval) {
        return calculateCounter(date.getTime(), timeInterval);
    }

    /**
     * Calculate counter for a specific time in seconds past 1970 and time interval
     * @param secondsPast1970 seconds past 1970
     * @param timeInterval time interval between new codes
     * @return counter based on seconds past 1970 and time interval
     */
    private long calculateCounter(long secondsPast1970, Duration timeInterval) {
        return secondsPast1970 / TimeUnit.SECONDS.toMillis(timeInterval.getSeconds());
    }

    /**
     * Calculate counter based on current time and a specific time interval
     * @param timeInterval time interval between new codes
     * @return counter based on current time and a specific time interval
     */
    private long calculateCounter(Duration timeInterval) {
        return System.currentTimeMillis() / TimeUnit.SECONDS.toMillis(timeInterval.getSeconds());
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
