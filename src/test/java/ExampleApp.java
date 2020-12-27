public class ExampleApp {
    public static void main(String[] args) {

        String secret = "VV3KOX7UQJ4KYAKOHMZPPH3US4CJIMH6F3ZKNB5C2OOBQ6V2KIYHM27Q";
//        String secret = "DREERRRR";

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
