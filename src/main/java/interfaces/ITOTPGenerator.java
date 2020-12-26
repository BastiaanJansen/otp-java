package interfaces;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

public interface ITOTPGenerator {
    String generate();
    String generate(Instant instant);
    String generate(Date date);
    String generate(long secondsPast1970);
    boolean verify(String code);
    Duration getPeriod();
}
