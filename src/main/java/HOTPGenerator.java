import interfaces.IHOTPGenerator;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;

/**
 * Generates counter-based one-time passwords
 * @author Bastiaan Jansen
 */
public class HOTPGenerator extends OneTimePasswordGenerator implements IHOTPGenerator {

    /**
     * Constructs generator with default values
     * @param secret used to generate hash
     */
    public HOTPGenerator(final String secret) {
        super(HMACAlgorithm.SHA1, secret);
    }

    /**
     * Constructs generator with custom password length
     * @param passwordLength number of digits for generated code in range 6...8
     * @param secret used to generate hash
     */
    public HOTPGenerator(final int passwordLength, final String secret) {
        super(passwordLength, HMACAlgorithm.SHA1, secret);
    }

    /**
     * Constructs generator from a OTPAuth URI
     * @param uri OTPAuth URI
     * @throws UnsupportedEncodingException when URI query can't be encodede
     */
    public HOTPGenerator(URI uri) throws UnsupportedEncodingException {
        super(uri);
    }

    /**
     * Generate a counter-based one-time password
     * @param counter how many times time interval has passed since 1970
     * @return generated HOTP code
     * @throws IllegalArgumentException when code could not be generated
     */
    @Override
    public String generate(long counter) throws IllegalArgumentException {
        return super.generate(BigInteger.valueOf(counter));
    }
}
