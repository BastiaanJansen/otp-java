public class ExampleApp {
    public static void main(String[] args) {

        String secret = "VV3KOX7UQJ4KYAKOHMZPPH3US4CJIMH6F3ZKNB5C2OOBQ6V2KIYHM27Q";

        TOTPGenerator totp = new TOTPGenerator(secret);
        HOTPGenerator hotp = new HOTPGenerator(secret);

        try {
            String code = hotp.generate(10);
            System.out.println(code);

            boolean isValid = hotp.verify(code, 8, 2);
            System.out.println(isValid);
        } catch (IllegalStateException e) {
            e.printStackTrace();
        }
    }
}
