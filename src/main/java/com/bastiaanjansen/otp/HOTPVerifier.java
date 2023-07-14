package com.bastiaanjansen.otp;

public class HOTPVerifier {

    private final HOTPGenerator hotpGenerator;
    private final SingleUseTokenStorageProvider singleUseTokenStorageProvider;

    protected HOTPVerifier(HOTPGenerator hotpGenerator, SingleUseTokenStorageProvider singleUseTokenStorageProvider) {
        this.hotpGenerator = hotpGenerator;
        this.singleUseTokenStorageProvider = singleUseTokenStorageProvider;
    }

    public boolean verify(final String code, final long counter) {
        return verify(code, counter, 0);
    }

    public boolean verify(final String code, final long counter, final int delayWindow) {
        if (code.length() != hotpGenerator.getPasswordLength()) {
            return false;
        }

        SingleUseTokenDetails singleUseTokenDetails = new SingleUseTokenDetails(hotpGenerator.getSecret(), code);

        if (singleUseTokenStorageProvider.contains(singleUseTokenDetails)) {
            return false;
        }

        for (int i = -delayWindow; i <= delayWindow; i++) {
            String currentCode = hotpGenerator.generate(counter + i);
            if (code.equals(currentCode)) {
                singleUseTokenStorageProvider.put(singleUseTokenDetails);
                return true;
            }
        }

        return false;
    }
}
