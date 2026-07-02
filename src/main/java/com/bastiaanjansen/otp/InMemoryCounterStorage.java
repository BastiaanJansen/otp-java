package com.bastiaanjansen.otp;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Built-in in-memory backend for {@link CounterStorage}, keeping the last used counter per identifier.
 * <p>
 * Create one shared instance for the whole application and bind it to an identifier per verification with
 * {@link #forIdentifier(String)}:
 * <pre>{@code
 * TOTPGenerator totpGenerator = new TOTPGenerator.Builder(secret)
 *         .withCounterStorage(counterStorage.forIdentifier(userId))
 *         .build();
 * }</pre>
 * Note: because counters are only kept in the memory of a single JVM, this implementation does not prevent replay
 * across multiple application instances, and entries are kept for as long as this instance lives. For distributed
 * systems, implement {@link CounterStorage} with a shared store such as Redis or Hazelcast.
 */
public class InMemoryCounterStorage {

    private final ConcurrentMap<String, Long> lastUsedCounters = new ConcurrentHashMap<>();

    /**
     * Creates a counter storage bound to the given identifier, backed by this instance.
     *
     * @param identifier identifier to store the last used counter by, for example a user id
     * @return counter storage bound to the identifier
     */
    public CounterStorage forIdentifier(final String identifier) {
        return counter -> markAsUsed(identifier, counter);
    }

    private boolean markAsUsed(final String identifier, final long counter) {
        while (true) {
            Long lastUsed = lastUsedCounters.putIfAbsent(identifier, counter);
            if (lastUsed == null) return true;
            if (counter <= lastUsed) return false;
            if (lastUsedCounters.replace(identifier, lastUsed, counter)) return true;
        }
    }
}
