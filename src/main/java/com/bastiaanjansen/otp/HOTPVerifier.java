package com.bastiaanjansen.otp;

public interface HOTPVerifier {
    boolean verify(final String code, final long counter);
    boolean verify(final String code, final long counter, final int delayWindow);
}
