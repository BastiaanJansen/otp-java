package com.bastiaanjansen.otp;

import com.bastiaanjansen.otp.helpers.URIHelper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.apache.commons.codec.binary.Base32;

/**
 * Generates one-time passwords
 *
 * @author Bastiaan Jansen
 */
public class OTPGenerator {
    private final static String URL_SCHEME = "otpauth";

    /**
     * Number of digits for generated code in range 6...8, defaults to 6
     */
    protected final int passwordLength;

    /**
     * Hashing algorithm used to generate code, defaults to SHA1
     */
    protected final HMACAlgorithm algorithm;

    /**
     * Secret key used to generate the code, this should be a base32 string
     */
    protected final byte[] secret;

    /**
     * Constructs the generator with custom password length and hashing algorithm
     *
     * @param passwordLength number of digits for generated code in range 6...8
     * @param algorithm      HMAC hash algorithm used to hash data
     * @param secret         used to generate hash
     */
    protected OTPGenerator(final int passwordLength, final HMACAlgorithm algorithm, final byte[] secret) {
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

    public byte[] getSecret() {
        return secret;
    }

    /**
     * Checks whether a code is valid for a specific counter with a delay window of 0
     *
     * @param code    an OTP code
     * @param counter how many times time interval has passed since 1970
     * @return a boolean, true if code is valid, otherwise false
     */
    public boolean verify(final String code, final long counter) {
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
    public boolean verify(final String code, final long counter, final int delayWindow) {
        if (code.length() != passwordLength) return false;

        for (int i = -delayWindow; i <= delayWindow; i++) {
            String currentCode = generateCode(counter + i);
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
    protected String generateCode(final long counter) throws IllegalStateException {
        byte[] secretBytes = decodeBase32(secret);
        byte[] counterBytes = longToBytes(counter);

        byte[] hash;

        try {
            hash = generateHash(secretBytes, counterBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException();
        }

        return getCodeFromHash(hash);
    }

    /**
     * Generate an OTPAuth URI
     *
     * @param type of OTPAuth URI: totp or hotp
     * @param path contains issuer and account name
     * @param query items of URI
     * @return created OTPAuth URI
     * @throws URISyntaxException when URI cannot be created
     */
    protected URI getURI(final String type, final String path, final Map<String, String> query) throws URISyntaxException {
        query.put(URIHelper.DIGITS, String.valueOf(passwordLength));
        query.put(URIHelper.ALGORITHM, algorithm.name());
        query.put(URIHelper.SECRET, new String(secret, StandardCharsets.UTF_8));
        return URIHelper.createURI(URL_SCHEME, type, path, query);
    }

    /**
     * Decode a base32 value to bytes array
     *
     * @param value base32 value
     * @return bytes array
     */
    private byte[] decodeBase32(final byte[] value) {
        Base32 codec = new Base32();
        return codec.decode(value);
    }

    /**
     * Convert a long value tp bytes array
     *
     * @param value long value
     * @return bytes array
     */
    private byte[] longToBytes(final long value) {
        return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
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
    private byte[] generateHash(final byte[] secret, final byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
        // Create a secret key with correct SHA algorithm
        SecretKeySpec signKey = new SecretKeySpec(secret, "RAW");
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
    private String getCodeFromHash(final byte[] hash) {
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

    /**
     * Abstract OTP builder
     *
     * @author Bastiaan Jansen
     * @param <B> concrete builder class
     */
    protected abstract static class Builder<B, G> {
        /**
         * Number of digits for generated code in range 6...8, defaults to 6
         */
        protected int passwordLength;

        /**
         * Hashing algorithm used to generate code, defaults to SHA1
         */
        protected HMACAlgorithm algorithm;

        /**
         * Secret key used to generate the code, this should be a base32 string
         */
        protected byte[] secret;

        /**
         * Default value for password length
         */
        public static final int DEFAULT_PASSWORD_LENGTH = 6;

        /**
         * Default value for HMAC Algorithm
         */
        public static final HMACAlgorithm DEFAULT_HMAC_ALGORITHM = HMACAlgorithm.SHA1;

        public Builder(final byte[] secret) {
            this.secret = secret;
            this.passwordLength = DEFAULT_PASSWORD_LENGTH;
            this.algorithm = DEFAULT_HMAC_ALGORITHM;
        }

        /**
         * Change password length of code
         *
         * @param passwordLength number of digits for generated code in range 6...8
         * @return concrete builder
         */
        public B withPasswordLength(final int passwordLength) {
            this.passwordLength = passwordLength;
            return getBuilder();
        }

        /**
         * Change hashing algorithm
         *
         * @param algorithm HMAC hashing algorithm
         * @return concrete builder
         */
        public B withAlgorithm(final HMACAlgorithm algorithm) {
            this.algorithm = algorithm;
            return getBuilder();
        }

        public byte[] getSecret() {
            return secret;
        }

        public int getPasswordLength() {
            return passwordLength;
        }

        public HMACAlgorithm getAlgorithm() {
            return algorithm;
        }

        public abstract B getBuilder();

        public abstract G build();
    }
}