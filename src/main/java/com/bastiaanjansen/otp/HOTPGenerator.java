package com.bastiaanjansen.otp;

import com.bastiaanjansen.otp.helpers.URIHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Generates counter-based one-time passwords
 *
 * @author Bastiaan Jansen
 * @see OTPGenerator
 */
public class HOTPGenerator extends OTPGenerator {
    private final static String OTP_TYPE = "hotp";

    /**
     * Constructs generator with custom password length
     * @param passwordLength number of digits for generated code in range 6...8
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret used to generate hash
     */
    public HOTPGenerator(final int passwordLength, final HMACAlgorithm algorithm, final byte[] secret) {
        super(passwordLength, algorithm, secret);
    }

    private HOTPGenerator(final HOTPGenerator.Builder builder) {
        super(builder.getPasswordLength(), builder.getAlgorithm(), builder.getSecret());
    }

    /**
     * Generate a counter-based one-time password
     * @param counter how many times time interval has passed since 1970
     * @return generated HOTP code
     * @throws IllegalArgumentException when code could not be generated
     */
    public String generate(long counter) throws IllegalArgumentException {
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
        query.put(URIHelper.COUNTER, String.valueOf(counter));

        String path = account.isEmpty() ? issuer : String.format("%s:%s", issuer, account);

        return getURI(OTP_TYPE, path, query);
    }

    /**
     * @author Bastiaan Jansen
     * @see HOTPGenerator
     */
    public static class Builder extends OTPGenerator.Builder<Builder, HOTPGenerator> {
        public Builder(final byte[] secret) {
            super(secret);
        }

        @Override
        public Builder getBuilder() {
            return this;
        }

        /**
         * Build the generator with specified options
         *
         * @return HOTPGenerator
         */
        @Override
        public HOTPGenerator build() {
            return new HOTPGenerator(this);
        }

        /**
         * Build a TOTPGenerator from an OTPAuth URI
         *
         * @param uri OTPAuth URI
         * @return HOTPGenerator
         * @throws URISyntaxException when URI cannot be parsed
         */
        public static HOTPGenerator fromOTPAuthURI(final URI uri) throws URISyntaxException {
            Map<String, String> query = URIHelper.queryItems(uri);

            String secret = Optional.ofNullable(query.get(URIHelper.SECRET))
                    .orElseThrow(() -> new IllegalArgumentException("Secret query parameter must be set"));

            HOTPGenerator.Builder builder = new HOTPGenerator.Builder(secret.getBytes());

            try {
                Optional.ofNullable(query.get(URIHelper.DIGITS)).map(Integer::parseInt).ifPresent(builder::withPasswordLength);
                Optional.ofNullable(query.get(URIHelper.ALGORITHM)).map(HMACAlgorithm::valueOf).ifPresent(builder::withAlgorithm);
            } catch (Exception e) {
                throw new URISyntaxException(uri.toString(), "URI could not be parsed");
            }

            return builder.build();
        }

        /**
         * Create a HOTPGenerator with default values
         *
         * @param secret used to generate hash
         * @return a HOTPGenerator with default values
         */
        public static HOTPGenerator withDefaultValues(final byte[] secret) {
            return new HOTPGenerator.Builder(secret).build();
        }
    }
}
