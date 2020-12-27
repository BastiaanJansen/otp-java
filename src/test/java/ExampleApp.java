import java.math.BigInteger;

public class ExampleApp {
    public static void main(String[] args) {

        String secret = "ABCDEFGHIJKLMNOP";

        TOTPGenerator totp = new TOTPGenerator(secret);

        try {
            String code = totp.generate();
            System.out.println(code);

            boolean isValid = totp.verify(code); // true
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }
}
