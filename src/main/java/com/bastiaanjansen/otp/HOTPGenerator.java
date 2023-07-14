package com.bastiaanjansen.otp;

import com.bastiaanjansen.otp.helpers.URIHelper;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public final class HOTPGenerator {

    private static final String URL_SCHEME = "otpauth";
    private static final int DEFAULT_PASSWORD_LENGTH = 6;
    private static final HMACAlgorithm DEFAULT_HMAC_ALGORITHM = HMACAlgorithm.SHA1;
    private static final String OTP_TYPE = "hotp";

    private final int passwordLength;

    private final HMACAlgorithm algorithm;

    private final byte[] secret;

    private HOTPGenerator(final Builder builder) {
        this.passwordLength = builder.passwordLength;
        this.algorithm = builder.algorithm;
        this.secret = builder.secret;
    }

    public static HOTPGenerator fromURI(final URI uri) throws URISyntaxException {
        Map<String, String> query = URIHelper.queryItems(uri);

        byte[] secret = Optional.ofNullable(query.get(URIHelper.SECRET))
                .map(String::getBytes)
                .orElseThrow(() -> new IllegalArgumentException("Secret query parameter must be set"));

        Builder builder = new Builder(secret);

        try {
            Optional.ofNullable(query.get(URIHelper.DIGITS))
                    .map(Integer::valueOf)
                    .ifPresent(builder::withPasswordLength);
            Optional.ofNullable(query.get(URIHelper.ALGORITHM))
                    .map(String::toUpperCase)
                    .map(HMACAlgorithm::valueOf)
                    .ifPresent(builder::withAlgorithm);
        } catch (Exception e) {
            throw new URISyntaxException(uri.toString(), "URI could not be parsed");
        }

        return builder.build();
    }

    public static HOTPGenerator withDefaultValues(final byte[] secret) {
        return new HOTPGenerator.Builder(secret).build();
    }

    public URI getURI(final int counter, final String issuer) throws URISyntaxException {
        return getURI(counter, issuer, "");
    }

    public URI getURI(final int counter, final String issuer, final String account) throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        query.put(URIHelper.COUNTER, String.valueOf(counter));

        return getURI(OTP_TYPE, issuer, account, query);
    }

    public int getPasswordLength() {
        return passwordLength;
    }

    public HMACAlgorithm getAlgorithm() {
        return algorithm;
    }

    public boolean verify(final String code, final long counter) {
        return verify(code, counter, 0);
    }

    public boolean verify(final String code, final long counter, final int delayWindow) {
        if (code.length() != passwordLength) return false;

        for (int i = -delayWindow; i <= delayWindow; i++) {
            String currentCode = generate(counter + i);
            if (code.equals(currentCode)) return true;
        }

        return false;
    }

    public String generate(final long counter) throws IllegalStateException {
        if (counter < 0)
            throw new IllegalArgumentException("Counter must be greater than or equal to 0");

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

    public URI getURI(final String type, final String issuer, final String account, final Map<String, String> query) throws URISyntaxException {
        query.put(URIHelper.DIGITS, String.valueOf(passwordLength));
        query.put(URIHelper.ALGORITHM, algorithm.name());
        query.put(URIHelper.SECRET, new String(secret, StandardCharsets.UTF_8));
        query.put(URIHelper.ISSUER, issuer);

        String path = account.isEmpty() ? URIHelper.encode(issuer) : String.format("%s:%s", URIHelper.encode(issuer), URIHelper.encode(account));

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

    private byte[] longToBytes(final long value) {
        return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
    }

    private byte[] generateHash(final byte[] secret, final byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
        // Create a secret key with correct SHA algorithm
        SecretKeySpec signKey = new SecretKeySpec(secret, "RAW");
        // Mac is 'message authentication code' algorithm (RFC 2104)
        Mac mac = Mac.getInstance(algorithm.getHMACName());
        mac.init(signKey);
        // Hash data with generated sign key
        return mac.doFinal(data);
    }

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

        // Left pad with 0s for an n-digit code
        return String.format("%0" + passwordLength + "d", truncatedHash);
    }

    public static final class Builder {

        private int passwordLength;

        private HMACAlgorithm algorithm;

        private final byte[] secret;

        public Builder(final byte[] secret) {
            if (secret.length == 0)
                throw new IllegalArgumentException("Secret must not be empty");

            this.secret = secret;
            this.passwordLength = DEFAULT_PASSWORD_LENGTH;
            this.algorithm = DEFAULT_HMAC_ALGORITHM;
        }

        public Builder withPasswordLength(final int passwordLength) {
            if (!passwordLengthIsValid(passwordLength))
                throw new IllegalArgumentException("Password length must be between 6 and 8 digits");

            this.passwordLength = passwordLength;
            return this;
        }

        public Builder withAlgorithm(final HMACAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public HOTPGenerator build() {
            return new HOTPGenerator(this);
        }

        private boolean passwordLengthIsValid(final int passwordLength) {
            return passwordLength >= 6 && passwordLength <= 8;
        }
    }
}
