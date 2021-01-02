package com.bastiaanjansen.otp.builders;

import com.bastiaanjansen.otp.HMACAlgorithm;

/**
 * Abstract OTP builder
 *
 * @author Bastiaan Jansen
 * @param <B> concrete builder class
 * @param <G> OTP generater which should be build by concrete builder
 */
public abstract class OTPBuilder<B, G> implements Builder<G> {

    /**
     * Number of digits for generated code in range 6...8, defaults to 6
     */
    protected int passwordLength;

    /**
     * Hashing algorithm used to generate code, defaults to SHA1
     */
    protected HMACAlgorithm algorithm;

    /**
     * Secret key used to generate the code, this should be a base32 string
     */
    protected byte[] secret;

    /**
     * Default value for password length
     */
    public static final int DEFAULT_PASSWORD_LENGTH = 6;

    /**
     * Default value for HMAC Algorithm
     */
    public static final HMACAlgorithm DEFAULT_HMAC_ALGORITHM = HMACAlgorithm.SHA1;

    public OTPBuilder(final byte[] secret) {
        this.secret = secret;
        this.passwordLength = DEFAULT_PASSWORD_LENGTH;
        this.algorithm = DEFAULT_HMAC_ALGORITHM;
    }

    /**
     * Change password length of code
     *
     * @param passwordLength number of digits for generated code in range 6...8
     * @return concrete builder
     */
    public B withPasswordLength(final int passwordLength) {
        this.passwordLength = passwordLength;
        return getBuilder();
    }

    /**
     * Change hashing algorithm
     *
     * @param algorithm HMAC hashing algorithm
     * @return concrete builder
     */
    public B withAlgorithm(final HMACAlgorithm algorithm) {
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

    public abstract B getBuilder();
}
