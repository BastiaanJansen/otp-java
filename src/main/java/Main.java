import javax.crypto.KeyGenerator;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;


public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {

        TOTPGenerator totp = new TOTPGenerator("DREERRRR");
        HOTPGenerator hotp = new HOTPGenerator("DREERRRR");

        try {
            String code = totp.generate();
            System.out.println(code);
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }
}
