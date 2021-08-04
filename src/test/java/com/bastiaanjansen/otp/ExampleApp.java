package com.bastiaanjansen.otp;

public class ExampleApp {
    public static void main(String[] args) {

        // Generate a secret, if you don't have one already
        byte[] secret = SecretGenerator.generate();

        // Create a TOTPGenerate instance
        TOTPGenerator.Builder builder = new TOTPGenerator.Builder(secret);
        TOTPGenerator totp = builder
                .withPasswordLength(6)
                .withAlgorithm(HMACAlgorithm.SHA1)
                .build();

        try {
            String code = totp.generate();
            System.out.println("Generated code: " + code);

            // To verify a codes
            totp.verify(code); // true
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }
}
