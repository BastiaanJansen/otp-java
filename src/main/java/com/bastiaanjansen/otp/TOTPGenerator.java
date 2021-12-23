package com.bastiaanjansen.otp;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Date;

public interface TOTPGenerator {
    String now();
    String at(final Instant instant);
    String at(final Date date);
    String at(final long secondsPast1970);

    URI getURI(final String issuer) throws URISyntaxException;
    URI getURI(final String issuer, final String account) throws URISyntaxException;
}
