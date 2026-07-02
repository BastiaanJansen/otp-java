package com.bastiaanjansen.otp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class InMemoryCounterStorageTest {

    private InMemoryCounterStorage storage;

    @BeforeEach
    void setUp() {
        storage = new InMemoryCounterStorage();
    }

    @Test
    void markAsUsedFirstTime_true() {
        assertThat(storage.forIdentifier("identifier").markAsUsed(100), is(true));
    }

    @Test
    void markAsUsedTwice_false() {
        storage.forIdentifier("identifier").markAsUsed(100);

        assertThat(storage.forIdentifier("identifier").markAsUsed(100), is(false));
    }

    @Test
    void markOlderCounterAsUsed_false() {
        storage.forIdentifier("identifier").markAsUsed(100);

        assertThat(storage.forIdentifier("identifier").markAsUsed(99), is(false));
    }

    @Test
    void markNewerCounterAsUsed_true() {
        storage.forIdentifier("identifier").markAsUsed(100);

        assertThat(storage.forIdentifier("identifier").markAsUsed(101), is(true));
    }

    @Test
    void markAsUsedWithDifferentIdentifier_true() {
        storage.forIdentifier("identifier").markAsUsed(100);

        assertThat(storage.forIdentifier("another-identifier").markAsUsed(100), is(true));
    }

    @Test
    void markAsUsedConcurrently_onlyOneSucceeds() throws Exception {
        int threads = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        try {
            List<Callable<Boolean>> tasks = IntStream.range(0, threads)
                    .mapToObj(i -> (Callable<Boolean>) () -> storage.forIdentifier("identifier").markAsUsed(100))
                    .collect(Collectors.toList());

            long succeeded = 0;
            for (Future<Boolean> future : executor.invokeAll(tasks)) {
                if (future.get()) succeeded++;
            }

            assertThat(succeeded, is(1L));
        } finally {
            executor.shutdown();
        }
    }
}
