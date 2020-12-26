public class ExampleApp {
    public static void main(String[] args) {

        String secret = "ABCDEFGHIJKLMNOP";

        TOTPGenerator totp = new TOTPGenerator(secret);
        HOTPGenerator hotp = new HOTPGenerator(secret);

        try {
            String code = totp.generate();
            System.out.println(code);

            boolean isValid = totp.verify(code);
            System.out.println(isValid);
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }
}
