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
 * @see OTP
 */
public final class HOTP extends OTP implements HOTPGenerator, HOTPVerifier {
    private final static String OTP_TYPE = "hotp";

    private HOTP(final Builder builder) {
        super(builder);
    }

    /**
     * Build a TOTPGenerator from an OTPAuth URI
     *
     * @param uri OTPAuth URI
     * @return HOTP
     * @throws URISyntaxException when URI cannot be parsed
     */
    public static HOTP fromURI(final URI uri) throws URISyntaxException {
        Map<String, String> query = URIHelper.queryItems(uri);

        byte[] secret = Optional.ofNullable(query.get(URIHelper.SECRET))
                .map(String::getBytes)
                .orElseThrow(() -> new IllegalArgumentException("Secret query parameter must be set"));

        Builder builder = new Builder(secret);

        try {
            Optional.ofNullable(query.get(URIHelper.DIGITS))
                    .map(Integer::valueOf)
                    .ifPresent(builder::withPasswordLength);
            Optional.ofNullable(query.get(URIHelper.ALGORITHM))
                    .map(String::toUpperCase)
                    .map(HMACAlgorithm::valueOf)
                    .ifPresent(builder::withAlgorithm);
        } catch (Exception e) {
            throw new URISyntaxException(uri.toString(), "URI could not be parsed");
        }

        return builder.build();
    }

    /**
     * Create a com.bastiaanjansen.otp.HOTPGenerator with default values
     *
     * @param secret used to generate hash
     * @return a com.bastiaanjansen.otp.HOTPGenerator with default values
     */
    public static HOTP withDefaultValues(final byte[] secret) {
        return new HOTP.Builder(secret).build();
    }

    /**
     * Generate a counter-based one-time password
     * @param counter how many times time interval has passed since 1970
     * @return generated HOTP code
     * @throws IllegalArgumentException when code could not be generated
     */
    public String generate(long counter) throws IllegalArgumentException {
        return super.generate(counter);
    }

    /**
     * Create an OTPAuth URI for easy user on-boarding with only an issuer
     *
     * @param counter of URI
     * @param issuer name for URI
     * @return OTPAuth URI
     * @throws URISyntaxException when URI cannot be created
     */
    public URI getURI(final int counter, final String issuer) throws URISyntaxException {
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
    public URI getURI(final int counter, final String issuer, final String account) throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        query.put(URIHelper.COUNTER, String.valueOf(counter));

        return getURI(OTP_TYPE, issuer, account, query);
    }

    /**
     * @author Bastiaan Jansen
     * @see HOTP
     */
    public static class Builder extends OTP.Builder<HOTP, Builder> {
        public Builder(final byte[] secret) {
            super(secret);
        }

        @Override
        protected Builder getBuilder() {
            return this;
        }

        /**
         * Build the generator with specified options
         *
         * @return HOTP
         */
        @Override
        public HOTP build() {
            return new HOTP(this);
        }
    }
}
