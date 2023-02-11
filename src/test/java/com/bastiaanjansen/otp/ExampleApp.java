package com.bastiaanjansen.otp;

import java.time.Clock;
import java.time.Duration;

public class ExampleApp {
    public static void main(String[] args) {

        // Generate a secret, if you don't have one already
        byte[] secret = SecretGenerator.generate();
        Clock clock = Clock.systemUTC();

        // Create a TOTPGenerate instance
        TOTPGenerator totpGenerator = new TOTPGenerator.Builder(secret)
                .withHOTPGenerator(builder -> {
                    builder.withAlgorithm(HMACAlgorithm.SHA1);
                    builder.withPasswordLength(6);
                })
                .withClock(clock)
                .withPeriod(Duration.ofMinutes(15))
                .build();

        try {
            String code = totpGenerator.now();
            System.out.println("Generated code: " + code);

            // To verify a code
            totpGenerator.verify(code); // true
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }
}
