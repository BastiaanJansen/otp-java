package com.bastiaanjansen.otp;

/**
 * HMAC algorithm enum
 * @author Bastiaan Jansen
 */
public enum HMACAlgorithm {
    /**
     * HMAC hashing algorithm options
     */
    SHA1("HmacSHA1"), SHA256("HmacSHA256"), SHA512("HmacSHA512");

    private final String name;

    HMACAlgorithm(String name) {
        this.name = name;
    }

    public String getHMACName() {
        return name;
    }
}
