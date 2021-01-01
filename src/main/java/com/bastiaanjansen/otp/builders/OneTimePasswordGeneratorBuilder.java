package com.bastiaanjansen.otp.builders;

import com.bastiaanjansen.otp.HMACAlgorithm;

public abstract class OneTimePasswordGeneratorBuilder<CONCRETE_BUILDER, GENERATOR> {

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

    public OneTimePasswordGeneratorBuilder(byte[] secret) {
        this.secret = secret;
        this.passwordLength = DEFAULT_PASSWORD_LENGTH;
        this.algorithm = DEFAULT_HMAC_ALGORITHM;
    }

    public CONCRETE_BUILDER withPasswordLength(int passwordLength) {
        this.passwordLength = passwordLength;
        return getBuilder();
    }

    public CONCRETE_BUILDER withAlgorithm(HMACAlgorithm algorithm) {
        this.algorithm = algorithm;
        return getBuilder();
    }

    public abstract GENERATOR create();

    public abstract CONCRETE_BUILDER getBuilder();
}
