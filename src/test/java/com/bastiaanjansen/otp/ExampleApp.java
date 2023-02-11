package com.bastiaanjansen.otp;

import java.time.Duration;

public class ExampleApp {
    public static void main(String[] args) {

        // Generate a secret, if you don't have one already
//        byte[] secret = SecretGenerator.generate();
//
//        // Create a TOTPGenerate instance
//        TOTPGenerator.Builder builder = new TOTPGenerator.Builder(secret);
//        TOTPGenerator totpGenerator = builder
//                .withPasswordLength(6)
//                .withAlgorithm(HMACAlgorithm.SHA1)
//                .withPeriod(Duration.ofMinutes(15))
//                .build();
//
//        try {
//            String code = totpGenerator.now();
//            System.out.println("Generated code: " + code);
//
//            // To verify a codes
//            totpGenerator.verify(code); // true
//        } catch (IllegalStateException e) {
//            e.printStackTrace();
//        }
    }
}
