package com.bastiaanjansen.otp;

public class ExampleApp {
    public static void main(String[] args) {

        // Generate a secret, if you don't have one already
        byte[] secret = SecretGenerator.generate();

        // Create a TOTPGenerate instance with default values
        TOTPGenerator totp = new TOTPGenerator(secret);

        try {
            String code = totp.generate();
            System.out.println("Generated code: " + code);

            // To verify a code
            totp.verify(code); // true
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }
}
