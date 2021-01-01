package com.bastiaanjansen.otp;

import com.bastiaanjansen.otp.builders.TOTPGeneratorBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;

public class ExampleApp {
    public static void main(String[] args) throws URISyntaxException, UnsupportedEncodingException {

        // Generate a secret, if you don't have one already
        byte[] secret = SecretGenerator.generate();

        // Create a TOTPGenerate instance
        TOTPGeneratorBuilder builder = new TOTPGeneratorBuilder(secret);
        TOTPGenerator totp = builder
                .withPasswordLength(8)
                .withAlgorithm(HMACAlgorithm.SHA256)
                // How to prevent:
//                 .withOTPAuthURI(new URI("otpauth://totp/issuer?secret=ABCD&period=60"))
                .create();

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
