import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Date;

public class Main {

    public static void main(String[] args) {
        String secret = "DREERRRR";
        CounterBasedOneTimePasswordGenerator hotp = new CounterBasedOneTimePasswordGenerator(secret);
        TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(5), secret);

        try {
            System.out.println(totp.generate());
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }

}
