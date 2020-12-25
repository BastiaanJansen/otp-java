import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class TimeBasedOneTimePasswordGenerator extends OneTimePasswordGenerator {
    private final Duration timeInterval;

    public static final Duration DEFAULT_TIME_INTERVAL = Duration.ofSeconds(30);

    public TimeBasedOneTimePasswordGenerator(final String secret) {
        this(DEFAULT_TIME_INTERVAL, secret);
    }

    public TimeBasedOneTimePasswordGenerator(final Duration timeInterval, final String secret) {
        super(secret);
        this.timeInterval = timeInterval;
    }

    public TimeBasedOneTimePasswordGenerator(final Duration timeInterval, HMACAlgorithm algorithm, final String secret) {
        super(algorithm, secret);
        this.timeInterval = timeInterval;
    }

    public TimeBasedOneTimePasswordGenerator(final HMACAlgorithm algorithm, final String secret) {
        super(algorithm, secret);
        this.timeInterval = DEFAULT_TIME_INTERVAL;
    }

    public TimeBasedOneTimePasswordGenerator(final int passwordLength, final Duration timeInterval, final String secret) {
        super(passwordLength, secret);
        this.timeInterval = timeInterval;
    }

    public TimeBasedOneTimePasswordGenerator(final int passwordLength, final Duration timeInterval, final HMACAlgorithm algorithm, final String secret) {
        super(passwordLength, algorithm, secret);
        this.timeInterval = timeInterval;
    }

    public String generate() throws InvalidKeyException, NoSuchAlgorithmException {
        long counter = calculateCounter(timeInterval);
        return super.generate(counter);
    }

    public String generate(Date date) throws NoSuchAlgorithmException, InvalidKeyException {
        long timeSince1970 = date.getTime();
        return generate(timeSince1970);
    }

    public String generate(long secondsPast1970) throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException {
        if (!validateTime(secondsPast1970)) {
            throw new IllegalArgumentException();
        }
        long counter = calculateCounter(secondsPast1970, timeInterval);
        return super.generate(counter);
    }

    private long calculateCounter(long secondsPast1970, Duration timeInterval) {
        return secondsPast1970 / TimeUnit.SECONDS.toMillis(timeInterval.getSeconds());
    }

    private long calculateCounter(Duration timeInterval) {
        return System.currentTimeMillis() / TimeUnit.SECONDS.toMillis(timeInterval.getSeconds());
    }

    private boolean validateTime(long time) {
        return time > 0;
    }

}
