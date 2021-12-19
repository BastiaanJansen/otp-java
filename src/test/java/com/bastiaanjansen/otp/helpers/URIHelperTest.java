package com.bastiaanjansen.otp.helpers;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

class URIHelperTest {

    @Test
    void queryItemsWithOneQueryItem() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=SHA1");
        Map<String, String> query = URIHelper.queryItems(uri);
        String expected = "SHA1";

        assertThat(query.get("algorithm"), is(expected));
    }

    @Test
    void queryItemsWithTwoQueryItems() throws URISyntaxException {
        URI uri = new URI("otpauth://totp/issuer:account?algorithm=SHA1&secret=ABC");
        Map<String, String> query = URIHelper.queryItems(uri);
        String expected = "ABC";

        assertThat(query.get("secret"), is(expected));
    }

    @Test
    void createURI_doesNotThrow() {
        Map<String, String> query = new HashMap<>();

        assertDoesNotThrow(() -> URIHelper.createURI("scheme", "host", "path", query));
    }

    @Test
    void createURIWithOneQueryItem() throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        query.put("test", "1");
        URI uri = URIHelper.createURI("scheme", "host", "path", query);
        String expected = "scheme://host/path?test=1";

        assertThat(uri.toString(), is(expected));
    }

    @Test
    void createURIWithTwoQueryItems() throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        query.put("test", "1");
        query.put("test2", "2");
        URI uri = URIHelper.createURI("scheme", "host", "path", query);
        String expected = "scheme://host/path?test2=2&test=1";

        assertThat(uri.toString(), is(expected));
    }
}