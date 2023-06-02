package com.bastiaanjansen.otp;

public final interface SingleUseTokenStorageProvider<T> {

    void put(T identifier, String otp);

    boolean contains(T identifier);

}