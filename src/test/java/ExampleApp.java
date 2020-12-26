import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ExampleApp {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, URISyntaxException, UnsupportedEncodingException {

        TOTPGenerator totp = new TOTPGenerator(new URI("otpauth://totp/test?secret=DREERRRR&algorithm=SHA1&digits=6&period=30"));
        HOTPGenerator hotp = new HOTPGenerator("DREERRRR");

        try {
            String code = totp.generate();
            System.out.println(code);
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }
}
