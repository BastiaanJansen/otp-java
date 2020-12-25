public class OneTimePasswordGenerator {
    private int passwordLength;
    private HMACAlgorithmType HMACAlgorithm;

    public static final int DEFAULT_PASSWORD_LENGTH = 6;
    public static final HMACAlgorithmType DEFAULT_HMAC_ALGORITHM = HMACAlgorithmType.SHA1;

    public OneTimePasswordGenerator() {
        this(DEFAULT_PASSWORD_LENGTH, DEFAULT_HMAC_ALGORITHM);
    }

    public OneTimePasswordGenerator(final int passwordLength) {
        this(passwordLength, DEFAULT_HMAC_ALGORITHM);
    }

    public OneTimePasswordGenerator(final HMACAlgorithmType algorithm) {
        this(DEFAULT_PASSWORD_LENGTH, algorithm);
    }

    public OneTimePasswordGenerator(final int passwordLength, final HMACAlgorithmType algorithm) {
        this.passwordLength = passwordLength;
        this.HMACAlgorithm = algorithm;
    }
}
