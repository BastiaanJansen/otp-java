import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import static org.junit.jupiter.api.Assertions.*;

class TOTPGeneratorTest {

    private String secret = "ABCDEFGHIJKLMNOP";

    @Test
    void generateBasedOnSecondsPast1970() {
        TOTPGenerator generator = new TOTPGenerator(secret);
        assertEquals("771577", generator.generate(1));
    }

    @Test
    void generateWithEightDigits() {
        TOTPGenerator generator = new TOTPGenerator(8, secret);
        assertEquals("36771577", generator.generate(1));
    }

    @Test
    void generateWithInstant() {
        TOTPGenerator generator = new TOTPGenerator(secret);
        assertEquals("771577", generator.generate(Instant.ofEpochMilli(1)));
    }

    @Test
    void generateWithDate() {
        TOTPGenerator generator = new TOTPGenerator(secret);
        Date date = new GregorianCalendar(2014, Calendar.FEBRUARY, 11).getTime();
        assertEquals("309037", generator.generate(date));
    }

    @Test
    void generateWithCustomTimeInterval() {
        TOTPGenerator generator = new TOTPGenerator(Duration.ofSeconds(60), secret);
        assertEquals("771577", generator.generate(1));
    }
}