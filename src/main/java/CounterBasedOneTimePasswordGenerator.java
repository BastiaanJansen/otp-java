import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class CounterBasedOneTimePasswordGenerator extends OneTimePasswordGenerator {

    public CounterBasedOneTimePasswordGenerator(final String secret) {
        super(secret);
    }

    public CounterBasedOneTimePasswordGenerator(final int passwordLength, final String secret) {
        super(passwordLength, secret);
    }

    public CounterBasedOneTimePasswordGenerator(final int passwordLength, final HMACAlgorithm algorithm, final String secret) {
        super(passwordLength, algorithm, secret);
    }

    public CounterBasedOneTimePasswordGenerator(final HMACAlgorithm algorithm, final String secret) {
        super(algorithm, secret);
    }

    public String generate(long counter) throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException {
        return super.generate(counter);
    }

}
