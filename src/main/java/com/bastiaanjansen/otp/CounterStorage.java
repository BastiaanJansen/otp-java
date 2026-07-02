package com.bastiaanjansen.otp;

/**
 * Stores the last used counter for a single identity, to prevent a one-time password from being used more than once.
 * <p>
 * A counter storage is bound to one identity (for example a user). When configured with
 * {@link TOTPGenerator.Builder#withCounterStorage(CounterStorage)}, {@link TOTPGenerator#verify(String)} accepts a
 * valid code only once. A built-in in-memory implementation is available via
 * {@link InMemoryCounterStorage#forIdentifier(String)}. For distributed systems, implement this interface with a
 * shared store such as Redis or Hazelcast, so a code consumed on one node cannot be replayed on another.
 */
public interface CounterStorage {

    /**
     * Atomically checks whether the given counter is greater than the last used counter and, if so, stores it as
     * the new last used counter.
     * <p>
     * Implementations must perform the check and store as one atomic operation, so that two concurrent calls with
     * the same counter cannot both return true.
     *
     * @param counter counter the one-time password was generated with
     * @return true when the counter was not used before and is now marked as used, false when it was already used
     */
    boolean markAsUsed(long counter);
}
