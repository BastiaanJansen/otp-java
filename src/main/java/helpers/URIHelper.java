package helpers;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

public class URIHelper {
    public static Map<String, String> queryItems(URI url) throws UnsupportedEncodingException {
        Map<String, String> items = new LinkedHashMap<String, String>();
        String query = url.getQuery();
        String[] pairs = query.split("&");
        for (String pair: pairs) {
            int index = pair.indexOf("=");
            items.put(URLDecoder.decode(pair.substring(0, index), "UTF-8"), URLDecoder.decode(pair.substring(index + 1), "UTF-8"));
        }
        return items;
    }
}
