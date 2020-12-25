/**
 * HMAC algorithm enum
 * @author Bastiaan Jansen
 */
public enum HMACAlgorithm {
    SHA1("HmacSHA1"), SHA256("HmacSHA256"), SHA512("HmacSHA512");

    private String name;

    private HMACAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
