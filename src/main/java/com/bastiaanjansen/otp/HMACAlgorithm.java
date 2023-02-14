package com.bastiaanjansen.otp;

/**
 * HMAC algorithm enum
 * @author Bastiaan Jansen
 */
public enum HMACAlgorithm {

    @Deprecated
    SHA1("HmacSHA1"),
    SHA224("HmacSHA224"),
    SHA256("HmacSHA256"),
    SHA384("HmacSHA384"),
    SHA512("HmacSHA512");

    private final String name;

    HMACAlgorithm(String name) {
        this.name = name;
    }

    public String getHMACName() {
        return name;
    }
}
