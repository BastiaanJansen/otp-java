package com.bastiaanjansen.otp;

public interface SingleUseTokenStorageProvider {

    void put(SingleUseTokenDetails details);

    boolean contains(SingleUseTokenDetails details);

}