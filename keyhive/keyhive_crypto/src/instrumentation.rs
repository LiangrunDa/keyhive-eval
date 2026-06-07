//! Lightweight crypto primitive counters for evaluation harnesses.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Protocol-visible crypto primitive counters used by the evaluation harness.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrimitiveCounters {
    pub hash: u64,
    pub kdf: u64,
    pub prf: u64,
    pub keygen: u64,
    pub dh: u64,
    pub aead_encrypt: u64,
    pub aead_decrypt: u64,
    pub sign: u64,
    pub verify: u64,
    /// Wall-clock nanoseconds spent inside public-key primitives (keygen, DH,
    /// sign, verify) and symmetric ones (hash, KDF, PRF, AEAD), respectively.
    /// Mirrors the OpenMLS provider's pubkey_ns/sym_ns split so the harness can
    /// report each protocol's asymmetric/symmetric/non-crypto wall-clock share.
    /// Only populated under the `std` feature; not part of the asserted series.
    pub pubkey_ns: u64,
    pub sym_ns: u64,
}

static HASH: AtomicUsize = AtomicUsize::new(0);
static KDF: AtomicUsize = AtomicUsize::new(0);
static PRF: AtomicUsize = AtomicUsize::new(0);
static KEYGEN: AtomicUsize = AtomicUsize::new(0);
static DH: AtomicUsize = AtomicUsize::new(0);
static AEAD_ENCRYPT: AtomicUsize = AtomicUsize::new(0);
static AEAD_DECRYPT: AtomicUsize = AtomicUsize::new(0);
static SIGN: AtomicUsize = AtomicUsize::new(0);
static VERIFY: AtomicUsize = AtomicUsize::new(0);
static PUBKEY_NS: AtomicU64 = AtomicU64::new(0);
static SYM_NS: AtomicU64 = AtomicU64::new(0);

/// Reset all counters for the current measurement phase.
pub fn reset() {
    HASH.store(0, Ordering::Relaxed);
    KDF.store(0, Ordering::Relaxed);
    PRF.store(0, Ordering::Relaxed);
    KEYGEN.store(0, Ordering::Relaxed);
    DH.store(0, Ordering::Relaxed);
    AEAD_ENCRYPT.store(0, Ordering::Relaxed);
    AEAD_DECRYPT.store(0, Ordering::Relaxed);
    SIGN.store(0, Ordering::Relaxed);
    VERIFY.store(0, Ordering::Relaxed);
    PUBKEY_NS.store(0, Ordering::Relaxed);
    SYM_NS.store(0, Ordering::Relaxed);
}

/// Snapshot all counters without resetting them.
pub fn snapshot() -> PrimitiveCounters {
    PrimitiveCounters {
        hash: HASH.load(Ordering::Relaxed) as u64,
        kdf: KDF.load(Ordering::Relaxed) as u64,
        prf: PRF.load(Ordering::Relaxed) as u64,
        keygen: KEYGEN.load(Ordering::Relaxed) as u64,
        dh: DH.load(Ordering::Relaxed) as u64,
        aead_encrypt: AEAD_ENCRYPT.load(Ordering::Relaxed) as u64,
        aead_decrypt: AEAD_DECRYPT.load(Ordering::Relaxed) as u64,
        sign: SIGN.load(Ordering::Relaxed) as u64,
        verify: VERIFY.load(Ordering::Relaxed) as u64,
        pubkey_ns: PUBKEY_NS.load(Ordering::Relaxed),
        sym_ns: SYM_NS.load(Ordering::Relaxed),
    }
}

/// Run `f`, adding its wall-clock duration to the public-key bucket, and return
/// its result. Wrap only the asymmetric primitive itself, not surrounding
/// symmetric work (e.g. for DH, wrap the `diffie_hellman` call but not the KDF
/// that derives a key from it), so the buckets stay non-overlapping leaves.
#[cfg(feature = "std")]
#[inline]
pub(crate) fn timed_pubkey<R>(f: impl FnOnce() -> R) -> R {
    let t = std::time::Instant::now();
    let r = f();
    PUBKEY_NS.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
    r
}

/// As [`timed_pubkey`] but for symmetric primitives (hash, KDF, PRF, AEAD).
#[cfg(feature = "std")]
#[inline]
pub(crate) fn timed_sym<R>(f: impl FnOnce() -> R) -> R {
    let t = std::time::Instant::now();
    let r = f();
    SYM_NS.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
    r
}

// In `no_std` builds there is no clock; the wrappers still exist so the call
// sites compile, but they only run the closure (pubkey_ns/sym_ns stay zero).
#[cfg(not(feature = "std"))]
#[inline]
pub(crate) fn timed_pubkey<R>(f: impl FnOnce() -> R) -> R {
    f()
}

#[cfg(not(feature = "std"))]
#[inline]
pub(crate) fn timed_sym<R>(f: impl FnOnce() -> R) -> R {
    f()
}

#[inline]
pub(crate) fn hash() {
    HASH.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn kdf() {
    KDF.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn prf() {
    PRF.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn keygen() {
    KEYGEN.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn dh() {
    DH.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn aead_encrypt() {
    AEAD_ENCRYPT.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn aead_decrypt() {
    AEAD_DECRYPT.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn sign() {
    SIGN.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub(crate) fn verify() {
    VERIFY.fetch_add(1, Ordering::Relaxed);
}
