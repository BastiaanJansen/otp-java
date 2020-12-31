import org.apache.commons.codec.binary.Base32;

import java.security.SecureRandom;

/**
 * A secret generator to generate OTP secrets
 *
 * @author Bastiaan Jansen
 */
public class SecretGenerator {

    public final static int DEFAULT_BITS = 160;

    /**
     * Generate an OTP base32 secret with default amount of bits
     *
     * @return generated secret
     */
    public static String generate() {
        return generate(DEFAULT_BITS);
    }

    /**
     * Generate an OTP base32 secret
     *
     * @param bits length, this should match the length of the HMAC algorithm type:
     *             SHA1: 160 bits
     *             SHA256: 256 bits
     *             SHA512: 512 bits
     * @return generated secret
     */
    public static String generate(final int bits) {
        if (bits <= 0)
            throw new IllegalArgumentException("Bits must be higher than 0");

        byte[] bytes = new byte[bits * 8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);

        return new Base32().encodeToString(bytes);
    }

}
