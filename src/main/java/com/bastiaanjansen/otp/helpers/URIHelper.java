package com.bastiaanjansen.otp.helpers;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A URI utility class with helper methods
 *
 * @author Bastiaan Jansen
 */
public class URIHelper {
    /**
     * Get a map of query items from URI
     *
     * @param uri to get query items from
     * @return map of query items from URI
     * @throws UnsupportedEncodingException when URI cannot be decoded
     */
    public static Map<String, String> queryItems(URI uri) throws UnsupportedEncodingException {
        Map<String, String> items = new LinkedHashMap<String, String>();
        String query = uri.getQuery();
        String[] pairs = query.split("&");
        for (String pair: pairs) {
            int index = pair.indexOf("=");
            items.put(URLDecoder.decode(pair.substring(0, index), "UTF-8"), URLDecoder.decode(pair.substring(index + 1), "UTF-8"));
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

        for (int i = 0; i < queryKeys.length; i++) {
            String sign = i == 0 ? "?" : "&";
            String key = queryKeys[i];
            uriString.append(String.format("%s%s=%s", sign, key, query.get(key)));

        }

        return new URI(uriString.toString());
    }
}
