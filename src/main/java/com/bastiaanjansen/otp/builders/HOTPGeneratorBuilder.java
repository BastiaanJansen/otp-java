package com.bastiaanjansen.otp.builders;

import com.bastiaanjansen.otp.HOTPGenerator;
import com.bastiaanjansen.otp.helpers.URIHelper;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Map;

/**
 * @author Bastiaan Jansen
 * @see OTPBuilder
 * @see HOTPGenerator
 */
public class HOTPGeneratorBuilder extends OTPBuilder<HOTPGeneratorBuilder, HOTPGenerator> {

    public HOTPGeneratorBuilder(final byte[] secret) {
        super(secret);
    }

    @Override
    public HOTPGeneratorBuilder getBuilder() {
        return this;
    }

    /**
     * Build the generator with specified options
     *
     * @return HOTPGenerator
     */
    @Override
    public HOTPGenerator build() {
        return new HOTPGenerator(passwordLength, secret);
    }

    /**
     * Build a TOTPGenerator from an OTPAuth URI
     *
     * @param uri OTPAuth URI
     * @return HOTPGenerator
     * @throws UnsupportedEncodingException when URI cannot be decoded
     */
    public static HOTPGenerator fromOTPAuthURI(final URI uri) throws UnsupportedEncodingException {
        Map<String, String> query = URIHelper.queryItems(uri);

        String secret = query.get("secret");
        if (secret == null) throw new IllegalArgumentException("Secret query parameter must be set");

        HOTPGeneratorBuilder builder = new HOTPGeneratorBuilder(secret.getBytes());

        return builder.build();
    }
}
