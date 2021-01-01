package com.bastiaanjansen.otp.builders;

import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.helpers.URIHelper;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Map;

public abstract class OneTimePasswordGeneratorBuilder<CONCRETE_BUILDER, GENERATOR> implements Builder<GENERATOR> {

    protected byte[] secret;
    protected int passwordLength;
    protected HMACAlgorithm algorithm;

    /**
     * Default value for password length
     */
    public static final int DEFAULT_PASSWORD_LENGTH = 6;

    /**
     * Default value for HMAC Algorithm
     */
    public static final HMACAlgorithm DEFAULT_HMAC_ALGORITHM = HMACAlgorithm.SHA1;

    public OneTimePasswordGeneratorBuilder(final byte[] secret) {
        this.secret = secret;
        this.passwordLength = DEFAULT_PASSWORD_LENGTH;
        this.algorithm = DEFAULT_HMAC_ALGORITHM;
    }

    public CONCRETE_BUILDER withPasswordLength(final int passwordLength) {
        this.passwordLength = passwordLength;
        return getBuilder();
    }

    public CONCRETE_BUILDER withAlgorithm(final HMACAlgorithm algorithm) {
        this.algorithm = algorithm;
        return getBuilder();
    }

    public byte[] getSecret() {
        return secret;
    }

    public int getPasswordLength() {
        return passwordLength;
    }

    public HMACAlgorithm getAlgorithm() {
        return algorithm;
    }

    public CONCRETE_BUILDER withOTPAuthURI(final URI uri) throws UnsupportedEncodingException {
        Map<String, String> query = URIHelper.queryItems(uri);

        String secret = query.get("secret");
        if (secret == null) throw new IllegalArgumentException("Secret query parameter must be set");

        this.passwordLength = Integer.parseInt(query.getOrDefault("digits", String.valueOf(DEFAULT_PASSWORD_LENGTH)));
        this.algorithm = HMACAlgorithm.valueOf(query.getOrDefault("algorithm", DEFAULT_HMAC_ALGORITHM.name()));
        this.secret = secret.getBytes();

        return getBuilder();
    }

    public abstract CONCRETE_BUILDER getBuilder();
}
