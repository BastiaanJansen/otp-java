import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HOTPGeneratorTest {

    private String secret = "ABCDEFGHIJKLMNOP";

    @Test
    void generateWithSixDigits() {
        HOTPGenerator generator = new HOTPGenerator(secret);
        assertEquals("317963", generator.generate(1));
    }

    @Test
    void generateWithSevenDigits() {
        HOTPGenerator generator = new HOTPGenerator(7, secret);
        assertEquals("6317963", generator.generate(1));
    }

    @Test
    void generateWithEightDigits() {
        HOTPGenerator generator = new HOTPGenerator(8, secret);
        assertEquals("36317963", generator.generate(1));
    }
}