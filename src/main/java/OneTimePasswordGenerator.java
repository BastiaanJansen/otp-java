import helpers.URIHelper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

/**
 * Generates one-time passwords
 * @author Bastiaan Jansen
 */
public class OneTimePasswordGenerator {
    /**
     * Number of digits for generated code in range 6...8, defaults to 6
     */
    protected final int passwordLength;

    /**
     * Hashing algorithm used to generate code, defaults to SHA1
     */
    protected final HMACAlgorithm algorithm;

    /**
     * Secret key used to generate the code
     */
    protected final String secret;

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
     *
     * @param secret used to generate hash
     */
    protected OneTimePasswordGenerator(final String secret) {
        this(DEFAULT_PASSWORD_LENGTH, DEFAULT_HMAC_ALGORITHM, secret);
    }

    /**
     * Constructs generator with a custom password length and default hashing algorithm
     *
     * @param passwordLength Number of digits for generated code in range 6...8
     * @param secret         used to generate hash
     */
    protected OneTimePasswordGenerator(final int passwordLength, final String secret) {
        this(passwordLength, DEFAULT_HMAC_ALGORITHM, secret);
    }

    /**
     * Constructs generator with a custom hashing algorithm and default password length
     *
     * @param algorithm HMAC hash algorithm used to hash data
     * @param secret    used to generate hash
     */
    protected OneTimePasswordGenerator(final HMACAlgorithm algorithm, final String secret) {
        this(DEFAULT_PASSWORD_LENGTH, algorithm, secret);
    }

    /**
     * Constructs generator from a OTPAuth URI
     *
     * @param uri OTPAuth URI
     * @throws UnsupportedEncodingException when URI query items can't be encoded
     */
    protected OneTimePasswordGenerator(URI uri) throws UnsupportedEncodingException {
        Map<String, String> query = URIHelper.queryItems(uri);

        String secret = query.get("secret");
        String passwordLength = query.get("digits");
        String algorithm = query.get("algorithm");
        HMACAlgorithm HMACAlgorithm = null;

        if (algorithm != null) {
            switch (algorithm) {
                case "SHA1":
                    HMACAlgorithm = HMACAlgorithm.SHA1;
                    break;
                case "SHA256":
                    HMACAlgorithm = HMACAlgorithm.SHA256;
                    break;
                case "SHA512":
                    HMACAlgorithm = HMACAlgorithm.SHA512;
                    break;
            }
        }

        if (secret == null) throw new IllegalArgumentException("Secret query parameter must be set");

        this.passwordLength = passwordLength == null ? DEFAULT_PASSWORD_LENGTH : Integer.valueOf(passwordLength);
        this.algorithm = algorithm == null ? DEFAULT_HMAC_ALGORITHM : HMACAlgorithm;
        this.secret = secret;
    }

    /**
     * Constructs the generator with custom password length and hashing algorithm
     *
     * @param passwordLength number of digits for generated code in range 6...8
     * @param algorithm      HMAC hash algorithm used to hash data
     * @param secret         used to generate hash
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

    public String getSecret() {
        return secret;
    }

    /**
     * Checks whether a code is valid for a specific counter with a delay window of 0
     *
     * @param code    an OTP code
     * @param counter how many times time interval has passed since 1970
     * @return a boolean, true if code is valid, otherwise false
     */
    public boolean verify(String code, long counter) {
        return verify(code, counter, 0);
    }

    /**
     * Checks whether a code is valid for a specific counter taking a delay window into account
     *
     * @param code an OTP codee
     * @param counter how many times time interval has passed since 1970
     * @param delayWindow window in which a code can still be deemed valid
     * @return a boolean, true if code is valid, otherwise false
     */
    public boolean verify(String code, long counter, int delayWindow) {
        if (code.length() != passwordLength) return false;

        for (int i = -delayWindow; i <= delayWindow; i++) {
            String currentCode = generate(BigInteger.valueOf(counter + i));
            if (code.equals(currentCode)) return true;
        }

        return false;
    }

    /**
     * Generate a code
     *
     * @param counter how many times time interval has passed since 1970
     * @return generated OTP code
     * @throws IllegalStateException when hashing algorithm throws an error
     */
    protected String generate(BigInteger counter) throws IllegalStateException {
        byte[] hash = generateHash(secret, counter.longValue());
        return getCodeFromHash(hash);
    }

    /**
     * Helper method to easily generate a hash based on a secret and counter
     *
     * @param secret    used to generate hash
     * @param counter   how many times time interval has passed since 1970
     * @return generated hash
     * @throws IllegalStateException when code could not be generated
     */
    private byte[] generateHash(String secret, long counter) {
        // Convert long type to bytes array
        // In Java, long takes 64 bits. sqrt(64) = 8, so allocate 8 bytes to ByteBuffer
        byte[] counterBytes = ByteBuffer.allocate(Long.BYTES).putLong(counter).array();

        // OTP secret must be a Base32 string
        // Create a HMAC signing key from the secret key
        Base32 codec = new Base32();
        byte[] decodedSecret = codec.decode(secret);

        try {
            return generateHash(decodedSecret, counterBytes);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new IllegalStateException();
        }
    }

    /**
     * Generate a hash based on an HMAC algorithm and secret
     *
     * @param secret    Base32 string converted to byte array used to generate hash
     * @param data      to hash
     * @return generated hash
     * @throws NoSuchAlgorithmException when algorithm does not exist
     * @throws InvalidKeyException      when secret is invalid
     */
    private byte[] generateHash(byte[] secret, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
        // Create a secret key with correct SHA algorithm
        SecretKeySpec signKey = new SecretKeySpec(secret, algorithm.getHMACName());
        // Mac is 'message authentication code' algorithm (RFC 2104)
        Mac mac = Mac.getInstance(algorithm.getHMACName());
        mac.init(signKey);
        // Hash data with generated sign key
        return mac.doFinal(data);
    }

    /**
     * Get code from hash with specified password length
     *
     * @param hash
     * @return OTP code
     */
    private String getCodeFromHash(byte[] hash) {
        /* Find mask to get last 4 digits:
        1. Set all bits to 1: ~0 -> 11111111 -> 255 decimal -> 0xFF
        2. Shift n (in this case 4, because we want the last 4 bits) bits to left with <<
        3. Negate the result: 1111 1100 -> 0000 0011
         */
        int mask = ~(~0 << 4);

        /* Get last 4 bits of hash as offset:
        Use the bitwise AND (&) operator to select last 4 bits
        Mask should be 00001111 = 15 = 0xF
        Last byte of hash & 0xF = last 4 bits:
        Example:
        Input: decimal 219 as binary: 11011011 &
        Mask: decimal 15 as binary:   00001111
        -----------------------------------------
        Output: decimal 11 as binary: 00001011
         */
        byte lastByte = hash[hash.length - 1];
        int offset = lastByte & mask;

        // Get 4 bytes from hash from offset to offset + 3
        byte[] truncatedHashInBytes = { hash[offset], hash[offset + 1], hash[offset + 2], hash[offset + 3] };

        // Wrap in ByteBuffer to convert bytes to long
        ByteBuffer byteBuffer = ByteBuffer.wrap(truncatedHashInBytes);
        long truncatedHash = byteBuffer.getInt();

        // Mask most significant bit
        truncatedHash &= 0x7FFFFFFF;

        // Modulo (%) truncatedHash by 10^passwordLength
        truncatedHash %= Math.pow(10, passwordLength);

        // Left pad with 0s for a n-digit code
        return String.format("%0" + passwordLength + "d", truncatedHash);
    }

    /**
     * Check if password is in range 6...8
     *
     * @param passwordLength number of digits for generated code in range 6...8
     * @return whether password is valid
     */
    private boolean validatePasswordLength(final int passwordLength) {
        return passwordLength >= 6 && passwordLength <= 8;
    }
}