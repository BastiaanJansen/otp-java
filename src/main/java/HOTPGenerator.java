/**
 * Generates counter-based one-time passwords
 * @author Bastiaan Jansen
 */
public class HOTPGenerator extends OneTimePasswordGenerator {

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
     * Generate a counter-based one-time password
     * @param counter
     * @return generated HOTP code
     * @throws IllegalArgumentException when code could not be generated
     */
    public String generate(long counter) throws IllegalArgumentException {
        return super.generate(counter);
    }

}
