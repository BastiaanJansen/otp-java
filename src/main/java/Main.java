import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class Main {

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException {
        String secret = "DREERRRR";
        CounterBasedOneTimePasswordGenerator hotp = new CounterBasedOneTimePasswordGenerator(secret);
        TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator(secret);
    }

}
