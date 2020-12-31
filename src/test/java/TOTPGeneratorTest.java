import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TOTPGeneratorTest {

    private String secret = "vv3kox7uqj4kyakohmzpph3us4cjimh6f3zknb5c2oobq6v2kiyhm27q";

    @Test
    void generateBasedOnSecondsPast1970() {
        TOTPGenerator generator = new TOTPGenerator(secret);
        assertEquals("455216", generator.generate(1));
    }

    @Test
    void generateWithEightDigits() {
        TOTPGenerator generator = new TOTPGenerator(8, secret);
        assertEquals("17455216", generator.generate(1));
    }

    @Test
    void generateWithInstant() {
        TOTPGenerator generator = new TOTPGenerator(secret);
        assertEquals("455216", generator.generate(Instant.ofEpochMilli(1)));
    }

    @Test
    void generateWithDate() {
        TOTPGenerator generator = new TOTPGenerator(secret);
        Date date = new GregorianCalendar(2014, Calendar.FEBRUARY, 11).getTime();
        assertEquals("019287", generator.generate(date));
    }

    @Test
    void generateWithCustomTimeInterval() {
        TOTPGenerator generator = new TOTPGenerator(Duration.ofSeconds(60), secret);
        assertEquals("455216", generator.generate(1));
    }
}