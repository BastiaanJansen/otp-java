package com.bastiaanjansen.otp.helpers;

import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

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

    @Test
    void createURI() {
        Map<String, String> query = new HashMap<>();
        query.put("test", "1");
        query.put("test2", "2");

        assertDoesNotThrow(() -> {
           URI uri = URIHelper.createURI("scheme", "host", "path", query);
           assertEquals("scheme://host/path?test2=2&test=1", uri.toString());
        });
    }
}