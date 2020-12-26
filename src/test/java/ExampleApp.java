public class ExampleApp {
    public static void main(String[] args) {

        TOTPGenerator totp = new TOTPGenerator("DREERRRR");
        HOTPGenerator hotp = new HOTPGenerator("DREERRRR");

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
