package com.bastiaanjansen.otp.helpers;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A URI utility class with helper methods
 *
 * @author Bastiaan Jansen
 */
public class URIHelper {
    
    public static final String DIGITS = "digits";
    public static final String SECRET = "secret";
    public static final String ALGORITHM = "algorithm";
    public static final String PERIOD = "period";
    public static final String COUNTER = "counter";
    public static final String ISSUER = "issuer";

    private URIHelper() {}

    /**
     * Get a map of query items from URI
     *
     * @param uri to get query items from
     * @return map of query items from URI
     */
    public static Map<String, String> queryItems(URI uri) {
        Map<String, String> items = new LinkedHashMap<>();
        String query = uri.getQuery();
        String[] pairs = query.split("&");

        for (String pair: pairs) {
            int index = pair.indexOf("=");
            try {
                items.put(
                        URLDecoder.decode(pair.substring(0, index), StandardCharsets.UTF_8.toString()),
                        URLDecoder.decode(pair.substring(index + 1), StandardCharsets.UTF_8.toString())
                );
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException("Encoding should be supported");
            }
        }
        return items;
    }

    /**
     * Create a URI based on a scheme, host, path and query items
     *
     * @param scheme of URI
     * @param host of URI
     * @param path of URI
     * @param query of URI
     * @return created URI
     * @throws URISyntaxException when URI cannot be created
     */
    public static URI createURI(String scheme, String host, String path, Map<String, String> query) throws URISyntaxException {
        StringBuilder uriString = new StringBuilder(String.format("%s://%s/%s", scheme, host, path));
        String[] queryKeys = query.keySet().toArray(new String[0]);

        try {
            for (int i = 0; i < queryKeys.length; i++) {
                String sign = i == 0 ? "?" : "&";
                String key = queryKeys[i];
                uriString.append(String.format("%s%s=%s", sign, key, URLEncoder.encode(query.get(key), StandardCharsets.UTF_8.toString())));
            }
        } catch (UnsupportedEncodingException e) {
            // Highly unlikely
            throw new IllegalArgumentException(e);
        }

        return new URI(uriString.toString());
    }
}
