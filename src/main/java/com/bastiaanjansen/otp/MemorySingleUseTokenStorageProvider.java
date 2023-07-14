package com.bastiaanjansen.otp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MemorySingleUseTokenStorageProvider implements SingleUseTokenStorageProvider {

    private final Map<byte[], String> storage = new HashMap<>();

    @Override
    public void put(SingleUseTokenDetails details) {
        this.storage.put(details.secret(), details.otp());
    }

    @Override
    public boolean contains(SingleUseTokenDetails details) {
        return storage.containsKey(details.secret()) && storage.get(details.secret()).equals(details.otp());
    }
}
