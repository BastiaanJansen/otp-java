package com.bastiaanjansen.otp;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

/**
 * Generates counter-based one-time passwords
 *
 * @author Bastiaan Jansen
 * @see OneTimePasswordGenerator
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
    public String generateCode(long counter) throws IllegalArgumentException {
        return super.generateCode(counter);
    }

    /**
     * Create an OTPAuth URI for easy user on-boarding with only an issuer
     *
     * @param counter of URI
     * @param issuer name for URI
     * @return OTPAuth URI
     * @throws URISyntaxException when URI cannot be created
     */
    public URI getURI(int counter, String issuer) throws URISyntaxException {
        return getURI(counter, issuer, "");
    }

    /**
     * Create an OTPAuth URI for easy user on-boarding with an issuer and account name
     *
     * @param counter of URI
     * @param issuer name for URI
     * @param account name for URI
     * @return OTPAuth URI
     * @throws URISyntaxException when URI cannot be created
     */
    public URI getURI(int counter, String issuer, String account) throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        query.put("counter", String.valueOf(counter));
        query.put("digits", String.valueOf(passwordLength));
        query.put("algorithm", algorithm.name());
        query.put("secret", secret);

        String path = account.isEmpty() ? issuer : String.format("%s:%s", issuer, account);

        return getURI("hotp", path, query);
    }
}
