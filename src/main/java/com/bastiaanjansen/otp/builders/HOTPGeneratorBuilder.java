package com.bastiaanjansen.otp.builders;

import com.bastiaanjansen.otp.HOTPGenerator;

import java.io.UnsupportedEncodingException;
import java.net.URI;

public class HOTPGeneratorBuilder extends OneTimePasswordGeneratorBuilder<HOTPGeneratorBuilder, HOTPGenerator> {

    public HOTPGeneratorBuilder(final byte[] secret) {
        super(secret);
    }

    @Override
    public HOTPGeneratorBuilder withOTPAuthURI(URI uri) throws UnsupportedEncodingException {
        return null;
    }

    @Override
    public HOTPGeneratorBuilder getBuilder() {
        return this;
    }

    @Override
    public HOTPGenerator create() {
        return new HOTPGenerator(passwordLength, secret);
    }
}
