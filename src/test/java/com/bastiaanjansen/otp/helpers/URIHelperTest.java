package com.bastiaanjansen.otp.helpers;

import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;

class URIHelperTest {

    @Test
    void queryItems() throws URISyntaxException, UnsupportedEncodingException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=SHA1&secret=ABC");
        Map<String, String> query = URIHelper.queryItems(uri);

        assertTrue(query.containsKey("algorithm"));
        assertTrue(query.containsKey("secret"));
        assertFalse(query.containsKey("digits"));
        assertEquals("SHA1", query.get("algorithm"));
        assertEquals("ABC", query.get("secret"));
    }
}