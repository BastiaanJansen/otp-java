import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OneTimePasswordGeneratorTest {

    private String secret = "ABCDEFGHIJKLMNOP";

    @Test
    void generateWithSHA1() {
        OneTimePasswordGenerator generator = new OneTimePasswordGenerator(HMACAlgorithm.SHA1, secret);
        assertEquals("250711", generator.generate(1));
    }

    @Test
    void generateWithSHA256() {
        OneTimePasswordGenerator generator = new OneTimePasswordGenerator(HMACAlgorithm.SHA256, secret);
        assertEquals("159317", generator.generate(1));
    }

    @Test
    void generateWithSHA512() {
        OneTimePasswordGenerator generator = new OneTimePasswordGenerator(HMACAlgorithm.SHA512, secret);
        assertEquals("997350", generator.generate(1));
    }
}