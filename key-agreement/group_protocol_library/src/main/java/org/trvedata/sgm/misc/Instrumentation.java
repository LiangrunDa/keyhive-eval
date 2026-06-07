package org.trvedata.sgm.misc;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;

/**
 * Thread-local crypto primitive counters for evaluation harnesses.
 */
public final class Instrumentation {
    private static final ThreadLocal<Counters> COUNTERS = ThreadLocal.withInitial(Counters::new);
    private static final ThreadLocal<Integer> SUPPRESS_DEPTH = ThreadLocal.withInitial(() -> 0);
    // Separate from SUPPRESS_DEPTH (which governs *counting*): this governs *timing*
    // only. The outermost timed primitive owns the whole subtree's time, so the
    // public-key / symmetric buckets never double-count nested calls.
    private static final ThreadLocal<Integer> TIME_DEPTH = ThreadLocal.withInitial(() -> 0);
    // Per-thread CPU time (not wall clock): the simulation is multi-threaded, so wall
    // time is contention-inflated and cannot be compared against the operation's CPU
    // time. CPU time lets us decompose total = crypto + non-crypto consistently.
    private static final ThreadMXBean THREAD_MX = ManagementFactory.getThreadMXBean();
    static {
        if (THREAD_MX.isThreadCpuTimeSupported() && !THREAD_MX.isThreadCpuTimeEnabled()) {
            THREAD_MX.setThreadCpuTimeEnabled(true);
        }
    }

    private Instrumentation() {
    }

    public interface CheckedSupplier<T> {
        T get();
    }

    public static final class Counters {
        public long hash;
        public long aeadEncrypt;
        public long aeadDecrypt;
        public long randomCalls;
        public long randomBytes;
        public long keygen;
        public long dh;
        public long hpkeEncrypt;
        public long hpkeDecrypt;
        public long sign;
        public long verify;
        public long prf;
        // Per-thread CPU nanoseconds spent inside public-key vs symmetric primitives,
        // and (set by the harness, not accumulated here) the total CPU of the whole
        // operation window. Timing only; not part of the asserted primitive counts.
        // non-crypto time = totalNanos - (pubkeyNanos + symNanos).
        public long pubkeyNanos;
        public long symNanos;
        public long totalNanos;

        private Counters copy() {
            Counters copy = new Counters();
            copy.hash = hash;
            copy.aeadEncrypt = aeadEncrypt;
            copy.aeadDecrypt = aeadDecrypt;
            copy.randomCalls = randomCalls;
            copy.randomBytes = randomBytes;
            copy.keygen = keygen;
            copy.dh = dh;
            copy.hpkeEncrypt = hpkeEncrypt;
            copy.hpkeDecrypt = hpkeDecrypt;
            copy.sign = sign;
            copy.verify = verify;
            copy.prf = prf;
            copy.pubkeyNanos = pubkeyNanos;
            copy.symNanos = symNanos;
            copy.totalNanos = totalNanos;
            return copy;
        }
    }

    public static void reset() {
        COUNTERS.set(new Counters());
        TIME_DEPTH.set(0);
    }

    /** Time {@code op} into the public-key bucket (only the outermost timed call counts). */
    public static <T> T timedPubkey(final CheckedSupplier<T> op) {
        return timed(true, op);
    }

    /** Time {@code op} into the symmetric (hash/KDF/AEAD) bucket. */
    public static <T> T timedSym(final CheckedSupplier<T> op) {
        return timed(false, op);
    }

    private static <T> T timed(final boolean pubkey, final CheckedSupplier<T> op) {
        final int depth = TIME_DEPTH.get();
        if (depth > 0) return op.get(); // nested: folds into the enclosing primitive's bucket
        TIME_DEPTH.set(depth + 1);
        final long t0 = THREAD_MX.getCurrentThreadCpuTime();
        try {
            return op.get();
        } finally {
            final long dt = THREAD_MX.getCurrentThreadCpuTime() - t0;
            TIME_DEPTH.set(depth);
            final Counters c = COUNTERS.get();
            if (pubkey) c.pubkeyNanos += dt;
            else c.symNanos += dt;
        }
    }

    public static Counters snapshot() {
        return COUNTERS.get().copy();
    }

    public static <T> T withSuppressed(final CheckedSupplier<T> supplier) {
        SUPPRESS_DEPTH.set(SUPPRESS_DEPTH.get() + 1);
        try {
            return supplier.get();
        } finally {
            SUPPRESS_DEPTH.set(SUPPRESS_DEPTH.get() - 1);
        }
    }

    private static boolean suppressed() {
        return SUPPRESS_DEPTH.get() > 0;
    }

    public static void recordHash() {
        if (!suppressed()) COUNTERS.get().hash++;
    }

    public static void recordAeadEncrypt() {
        if (!suppressed()) COUNTERS.get().aeadEncrypt++;
    }

    public static void recordAeadDecrypt() {
        if (!suppressed()) COUNTERS.get().aeadDecrypt++;
    }

    public static void recordRandomBytes(final int byteLength) {
        if (!suppressed()) {
            COUNTERS.get().randomCalls++;
            COUNTERS.get().randomBytes += byteLength;
        }
    }

    public static void recordKeygen() {
        if (!suppressed()) COUNTERS.get().keygen++;
    }

    public static void recordDh() {
        if (!suppressed()) COUNTERS.get().dh++;
    }

    public static void recordHpkeEncrypt() {
        if (!suppressed()) COUNTERS.get().hpkeEncrypt++;
    }

    public static void recordHpkeDecrypt() {
        if (!suppressed()) COUNTERS.get().hpkeDecrypt++;
    }

    public static void recordSign() {
        if (!suppressed()) COUNTERS.get().sign++;
    }

    public static void recordVerify() {
        if (!suppressed()) COUNTERS.get().verify++;
    }

    public static void recordPrf() {
        if (!suppressed()) COUNTERS.get().prf++;
    }
}
