import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Generates one-time passwords
 * @author Bastiaan Jansen
 */
public class OneTimePasswordGenerator {
    /**
     * Number of digits for generated code in range 6...8, defaults to 6
     */
    private final int passwordLength;

    /**
     * Hashing algorithm used to generate code, defaults to SHA1
     */
    private final HMACAlgorithm algorithm;

    /**
     * Secret key
     */
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

    /**
     * Default value for password length
     */
    public static final int DEFAULT_PASSWORD_LENGTH = 6;

    /**
     * Default value for HMAC Algorithm
     */
    public static final HMACAlgorithm DEFAULT_HMAC_ALGORITHM = HMACAlgorithm.SHA1;

    /**
     * Constructs generator with default values
     * @param secret secret key
     */
    protected OneTimePasswordGenerator(final String secret) {
        this(DEFAULT_PASSWORD_LENGTH, DEFAULT_HMAC_ALGORITHM, secret);
    }

    /**
     * Constructs the generator with a custom password length and default hashing algorithm
     * @param passwordLength
     * @param secret
     */
    protected OneTimePasswordGenerator(final int passwordLength, final String secret) {
        this(passwordLength, DEFAULT_HMAC_ALGORITHM, secret);
    }

    /**
     * Constructs the generator with a custom hashing algorithm and default password length
     * @param algorithm
     * @param secret
     */
    protected OneTimePasswordGenerator(final HMACAlgorithm algorithm, final String secret) {
        this(DEFAULT_PASSWORD_LENGTH, algorithm, secret);
    }

    /**
     * Constructs the generator with custom password length and hashing algorithm
     * @param passwordLength
     * @param algorithm
     * @param secret
     */
    protected OneTimePasswordGenerator(final int passwordLength, final HMACAlgorithm algorithm, final String secret) {
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

    /**
     * Generate a code
     * @param counter
     * @return otp code
     * @throws IllegalStateException when hashing algorithm throws an error
     */
    protected String generate(long counter) throws IllegalStateException {
        byte[] hash = generateHash(algorithm, secret, counter);

        int offset = hash[hash.length - 1] & 0xf;
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
        long otp = binary % DIGITS_POWER[passwordLength];
        return String.format("%0" + passwordLength + "d", otp);
    }

    /**
     * Helper method to easily generate a hash based on a secret and counter
     * @param algorithm
     * @param secret
     * @param counter
     * @return generated hash
     * @throws IllegalStateException
     */
    private byte[] generateHash(HMACAlgorithm algorithm, String secret, long counter) throws IllegalStateException {
        byte[] secretBytes = secret.getBytes();
        byte[] counterBytes = ByteBuffer.allocate(Long.BYTES).putLong(counter).array();
        try {
            return generateHash(algorithm, secretBytes, counterBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException();
        }
    }

    /**
     * Generate a hash based on an HMAC algorithm and secret
     * @param algorithm hash algorithm used to hash data
     * @param secret used to generate hash
     * @param data to hash
     * @return generated hash
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private byte[] generateHash(HMACAlgorithm algorithm, byte[] secret, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.toString());
        SecretKeySpec macKey = new SecretKeySpec(secret, "RAW");
        mac.init(macKey);

        return mac.doFinal(data);
    }

    /**
     * Check if password is in range 6...8
     * @param passwordLength
     * @return whether password is valid
     */
    private boolean validatePasswordLength(final int passwordLength) {
        return (passwordLength >= 6 || passwordLength <= 8);
    }
}
