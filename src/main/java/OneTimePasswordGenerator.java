import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class OneTimePasswordGenerator {
    private final int passwordLength;
    private final HMACAlgorithm algorithm;
    private final String secret;

    private static final long[] DIGITS_POWER = {
            1L,                // 0
            10L,               // 1
            100L,              // 2
            1_000L,            // 3
            10_000L,           // 4
            100_000L,          // 5
            1_000_000L,        // 6
            10_000_000L,       // 7
            100_000_000L,      // 8
            1_000_000_000L,    // 9
            10_000_000_000L,   // 10
            100_000_000_000L,  // 11
            1_000_000_000_000L // 12
    };

    public static final int DEFAULT_PASSWORD_LENGTH = 6;
    public static final HMACAlgorithm DEFAULT_HMAC_ALGORITHM = HMACAlgorithm.SHA1;

    public OneTimePasswordGenerator(final String secret) {
        this(DEFAULT_PASSWORD_LENGTH, DEFAULT_HMAC_ALGORITHM, secret);
    }

    public OneTimePasswordGenerator(final int passwordLength, final String secret) {
        this(passwordLength, DEFAULT_HMAC_ALGORITHM, secret);
    }

    public OneTimePasswordGenerator(final HMACAlgorithm algorithm, final String secret) {
        this(DEFAULT_PASSWORD_LENGTH, algorithm, secret);
    }

    public OneTimePasswordGenerator(final int passwordLength, final HMACAlgorithm algorithm, final String secret) throws IllegalArgumentException {
        if (!validatePasswordLength(passwordLength)) {
            throw new IllegalArgumentException("Password length must be between 6 and 8 digits");
        }

        this.passwordLength = passwordLength;
        this.algorithm = algorithm;
        this.secret = secret;
    }

    public int getPasswordLength() {
        return passwordLength;
    }

    public HMACAlgorithm getAlgorithm() {
        return algorithm;
    }

    protected String getSecret() {
        return secret;
    }

    protected String generate(long counter) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] hash = generateHash(algorithm, secret, counter);

        int offset = hash[hash.length - 1] & 0xf;
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
        long otp = binary % DIGITS_POWER[passwordLength];
        return String.format("%0" + passwordLength + "d", otp);
    }

    private byte[] generateHash(HMACAlgorithm algorithm, String secret, long counter) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] secretBytes = secret.getBytes();
        byte[] counterBytes = ByteBuffer.allocate(Long.BYTES).putLong(counter).array();
        return generateHash(algorithm, secretBytes, counterBytes);
    }

    private byte[] generateHash(HMACAlgorithm algorithm, byte[] secret, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.toString());
        SecretKeySpec macKey = new SecretKeySpec(secret, "RAW");
        mac.init(macKey);

        return mac.doFinal(data);
    }

    private boolean validatePasswordLength(final int passwordLength) {
        return (passwordLength >= 6 || passwordLength <= 8);
    }
}
