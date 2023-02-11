package com.bastiaanjansen.otp;

import com.bastiaanjansen.otp.helpers.URIHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.*;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public final class TOTPGenerator {
    private static final String OTP_TYPE = "totp";
    private static final Duration DEFAULT_PERIOD = Duration.ofSeconds(30);
    private static final Clock DEFAULT_CLOCK = Clock.system(ZoneId.systemDefault());

    private final Duration period;

    private final Clock clock;

    private final HOTPGenerator hotpGenerator;

    private TOTPGenerator(final Builder builder) {
        this.period = builder.period;
        this.clock = builder.clock;
        this.hotpGenerator = builder.hotpBuilder.build();
    }

    public static TOTPGenerator fromURI(URI uri) throws URISyntaxException {
        Map<String, String> query = URIHelper.queryItems(uri);

        byte[] secret = Optional.ofNullable(query.get(URIHelper.SECRET))
                .map(String::getBytes)
                .orElseThrow(() -> new IllegalArgumentException("Secret query parameter must be set"));

        Builder builder = new Builder(secret);

        try {
            Optional.ofNullable(query.get(URIHelper.PERIOD))
                    .map(Long::parseLong)
                    .map(Duration::ofSeconds)
                    .ifPresent(builder::withPeriod);
            Optional.ofNullable(query.get(URIHelper.DIGITS))
                    .map(Integer::valueOf)
                    .ifPresent(builder.hotpBuilder::withPasswordLength);
            Optional.ofNullable(query.get(URIHelper.ALGORITHM))
                    .map(String::toUpperCase)
                    .map(HMACAlgorithm::valueOf)
                    .ifPresent(builder.hotpBuilder::withAlgorithm);
        } catch (Exception e) {
            throw new URISyntaxException(uri.toString(), "URI could not be parsed");
        }

        return builder.build();
    }

    public static TOTPGenerator withDefaultValues(final byte[] secret) {
        return new TOTPGenerator.Builder(secret).build();
    }

    public String now() throws IllegalStateException {
        long counter = calculateCounter(clock, period);
        return hotpGenerator.generate(counter);
    }

    public String now(Clock clock) throws IllegalStateException {
        long counter = calculateCounter(clock, period);
        return hotpGenerator.generate(counter);
    }

    public String at(final Instant instant) throws IllegalStateException {
        return at(instant.getEpochSecond());
    }

    public String at(final Date date) throws IllegalStateException {
        long secondsSince1970 = TimeUnit.MILLISECONDS.toSeconds(date.getTime());
        return at(secondsSince1970);
    }

    public String at(final LocalDate date) throws IllegalStateException {
        long secondsSince1970 = date.atStartOfDay(clock.getZone()).toEpochSecond();
        return at(secondsSince1970);
    }

    public String at(final long secondsPast1970) throws IllegalArgumentException {
        if (!validateTime(secondsPast1970))
            throw new IllegalArgumentException("Time must be above zero");

        long counter = calculateCounter(secondsPast1970, period);
        return hotpGenerator.generate(counter);
    }

    public boolean verify(final String code) {
        long counter = calculateCounter(clock, period);
        return hotpGenerator.verify(code, counter);
    }

    /**
     * Checks whether a code is valid for a specific counter taking a delay window into account
     *
     * @param code an OTP code
     * @param delayWindow window in which a code can still be deemed valid
     * @return a boolean, true if code is valid, otherwise false
     */
    public boolean verify(final String code, final int delayWindow) {
        long counter = calculateCounter(clock, period);
        return hotpGenerator.verify(code, counter, delayWindow);
    }

    public URI getURI(final String issuer) throws URISyntaxException {
        return getURI(issuer, "");
    }

    public URI getURI(final String issuer, final String account) throws URISyntaxException {
        Map<String, String> query = new HashMap<>();
        query.put(URIHelper.PERIOD, String.valueOf(period.getSeconds()));

        return hotpGenerator.getURI(OTP_TYPE, issuer, account, query);
    }

    /**
     * Calculates time until next time window will be reached and a new totp should be generated
     *
     * @return a duration object with duration until next time window
     */
    public Duration durationUntilNextTimeWindow() {
        return durationUntilNextTimeWindow(clock);
    }

    public Duration durationUntilNextTimeWindow(Clock clock) {
        long timeInterval = period.toMillis();
        return Duration.ofMillis(timeInterval - clock.millis() % timeInterval);
    }

    public Duration getPeriod() {
        return period;
    }

    public Clock getClock() {
        return clock;
    }

    public HMACAlgorithm getAlgorithm() {
        return hotpGenerator.getAlgorithm();
    }

    public int getPasswordLength() {
        return hotpGenerator.getPasswordLength();
    }

    private long calculateCounter(final long secondsPast1970, final Duration period) {
        return TimeUnit.SECONDS.toMillis(secondsPast1970) / period.toMillis();
    }

    private long calculateCounter(final Clock clock, final Duration period) {
        return clock.millis() / period.toMillis();
    }

    private boolean validateTime(final long time) {
        return time > 0;
    }

    public static final class Builder {

        private Duration period;

        private Clock clock;

        private final HOTPGenerator.Builder hotpBuilder;

        public Builder(byte[] secret) {
            this.period = DEFAULT_PERIOD;
            this.clock = DEFAULT_CLOCK;
            this.hotpBuilder = new HOTPGenerator.Builder(secret);
        }

        public Builder withHOTPGenerator(Consumer<HOTPGenerator.Builder> builder) {
            builder.accept(hotpBuilder);
            return this;
        }

        public Builder withClock(Clock clock) {
            this.clock = clock;
            return this;
        }

        public Builder withPeriod(Duration period) {
            if (period.getSeconds() < 1) throw new IllegalArgumentException("Period must be at least 1 second");
            this.period = period;
            return this;
        }

        public TOTPGenerator build() {
            return new TOTPGenerator(this);
        }
    }
}
