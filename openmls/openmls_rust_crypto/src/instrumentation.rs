//! Experiment-only crypto instrumentation wrappers.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use openmls_memory_storage::MemoryStorage;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig,
        HpkeKeyPair, KemOutput, SignatureScheme,
    },
    OpenMlsProvider,
};
use tls_codec::SecretVLBytes;

use crate::{OpenMlsRustCrypto, RustCrypto};

/// Protocol-visible crypto primitive counters for TreeKEM evaluation runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PrimitiveCounters {
    pub hkdf_extract: u64,
    pub hmac: u64,
    pub hkdf_expand: u64,
    pub hash: u64,
    pub aead_encrypt: u64,
    pub aead_decrypt: u64,
    pub signature_key_gen: u64,
    pub verify_signature: u64,
    pub sign: u64,
    pub hpke_seal: u64,
    pub hpke_open: u64,
    pub hpke_setup_sender_and_export: u64,
    pub hpke_setup_receiver_and_export: u64,
    pub derive_hpke_keypair: u64,
    pub random_calls: u64,
    pub random_bytes: u64,
    /// Wall-clock nanoseconds spent inside public-key primitives (HPKE, signatures,
    /// keypair derivation) and symmetric ones (hash, KDF, HMAC, AEAD), respectively.
    /// Used only to test the paper's claim that the per-N cost is public-key for
    /// DCGKA vs symmetric for TreeKEM; not part of the asserted (deterministic) series.
    pub pubkey_ns: u64,
    pub sym_ns: u64,
}

#[derive(Debug, Default)]
struct CounterInner {
    hkdf_extract: AtomicU64,
    hmac: AtomicU64,
    hkdf_expand: AtomicU64,
    hash: AtomicU64,
    aead_encrypt: AtomicU64,
    aead_decrypt: AtomicU64,
    signature_key_gen: AtomicU64,
    verify_signature: AtomicU64,
    sign: AtomicU64,
    hpke_seal: AtomicU64,
    hpke_open: AtomicU64,
    hpke_setup_sender_and_export: AtomicU64,
    hpke_setup_receiver_and_export: AtomicU64,
    derive_hpke_keypair: AtomicU64,
    random_calls: AtomicU64,
    random_bytes: AtomicU64,
    pubkey_ns: AtomicU64,
    sym_ns: AtomicU64,
}

/// Shareable handle used by the benchmark harness to reset and snapshot a peer.
#[derive(Clone, Debug, Default)]
pub struct CounterHandle {
    inner: Arc<CounterInner>,
}

impl CounterHandle {
    pub fn reset(&self) {
        self.inner.hkdf_extract.store(0, Ordering::Relaxed);
        self.inner.hmac.store(0, Ordering::Relaxed);
        self.inner.hkdf_expand.store(0, Ordering::Relaxed);
        self.inner.hash.store(0, Ordering::Relaxed);
        self.inner.aead_encrypt.store(0, Ordering::Relaxed);
        self.inner.aead_decrypt.store(0, Ordering::Relaxed);
        self.inner.signature_key_gen.store(0, Ordering::Relaxed);
        self.inner.verify_signature.store(0, Ordering::Relaxed);
        self.inner.sign.store(0, Ordering::Relaxed);
        self.inner.hpke_seal.store(0, Ordering::Relaxed);
        self.inner.hpke_open.store(0, Ordering::Relaxed);
        self.inner
            .hpke_setup_sender_and_export
            .store(0, Ordering::Relaxed);
        self.inner
            .hpke_setup_receiver_and_export
            .store(0, Ordering::Relaxed);
        self.inner.derive_hpke_keypair.store(0, Ordering::Relaxed);
        self.inner.random_calls.store(0, Ordering::Relaxed);
        self.inner.random_bytes.store(0, Ordering::Relaxed);
        self.inner.pubkey_ns.store(0, Ordering::Relaxed);
        self.inner.sym_ns.store(0, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> PrimitiveCounters {
        PrimitiveCounters {
            hkdf_extract: self.inner.hkdf_extract.load(Ordering::Relaxed),
            hmac: self.inner.hmac.load(Ordering::Relaxed),
            hkdf_expand: self.inner.hkdf_expand.load(Ordering::Relaxed),
            hash: self.inner.hash.load(Ordering::Relaxed),
            aead_encrypt: self.inner.aead_encrypt.load(Ordering::Relaxed),
            aead_decrypt: self.inner.aead_decrypt.load(Ordering::Relaxed),
            signature_key_gen: self.inner.signature_key_gen.load(Ordering::Relaxed),
            verify_signature: self.inner.verify_signature.load(Ordering::Relaxed),
            sign: self.inner.sign.load(Ordering::Relaxed),
            hpke_seal: self.inner.hpke_seal.load(Ordering::Relaxed),
            hpke_open: self.inner.hpke_open.load(Ordering::Relaxed),
            hpke_setup_sender_and_export: self
                .inner
                .hpke_setup_sender_and_export
                .load(Ordering::Relaxed),
            hpke_setup_receiver_and_export: self
                .inner
                .hpke_setup_receiver_and_export
                .load(Ordering::Relaxed),
            derive_hpke_keypair: self.inner.derive_hpke_keypair.load(Ordering::Relaxed),
            random_calls: self.inner.random_calls.load(Ordering::Relaxed),
            random_bytes: self.inner.random_bytes.load(Ordering::Relaxed),
            pubkey_ns: self.inner.pubkey_ns.load(Ordering::Relaxed),
            sym_ns: self.inner.sym_ns.load(Ordering::Relaxed),
        }
    }
}

/// Wrapper around an OpenMLS crypto provider that records method-level counters.
#[derive(Debug)]
pub struct InstrumentedCrypto<C> {
    inner: C,
    counters: CounterHandle,
}

impl<C> InstrumentedCrypto<C> {
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            counters: CounterHandle::default(),
        }
    }

    pub fn counter_handle(&self) -> CounterHandle {
        self.counters.clone()
    }

    pub fn inner(&self) -> &C {
        &self.inner
    }

    fn increment(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Run `f`, adding its wall-clock duration to `bucket`. The inner provider's
    /// sub-operations do not re-enter this wrapper, so each counted call is a
    /// non-overlapping leaf and the buckets never double-count.
    fn timed<R>(bucket: &AtomicU64, f: impl FnOnce() -> R) -> R {
        let t = std::time::Instant::now();
        let r = f();
        bucket.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
        r
    }
}

impl<C: Default> Default for InstrumentedCrypto<C> {
    fn default() -> Self {
        Self::new(C::default())
    }
}

impl<C: OpenMlsCrypto> OpenMlsCrypto for InstrumentedCrypto<C> {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        self.inner.supports(ciphersuite)
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        self.inner.supported_ciphersuites()
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        Self::increment(&self.counters.inner.hkdf_extract);
        Self::timed(&self.counters.inner.sym_ns, || {
            self.inner.hkdf_extract(hash_type, salt, ikm)
        })
    }

    fn hmac(
        &self,
        hash_type: HashType,
        key: &[u8],
        message: &[u8],
    ) -> Result<SecretVLBytes, CryptoError> {
        Self::increment(&self.counters.inner.hmac);
        Self::timed(&self.counters.inner.sym_ns, || {
            self.inner.hmac(hash_type, key, message)
        })
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        Self::increment(&self.counters.inner.hkdf_expand);
        Self::timed(&self.counters.inner.sym_ns, || {
            self.inner.hkdf_expand(hash_type, prk, info, okm_len)
        })
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Self::increment(&self.counters.inner.hash);
        Self::timed(&self.counters.inner.sym_ns, || self.inner.hash(hash_type, data))
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Self::increment(&self.counters.inner.aead_encrypt);
        Self::timed(&self.counters.inner.sym_ns, || {
            self.inner.aead_encrypt(alg, key, data, nonce, aad)
        })
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Self::increment(&self.counters.inner.aead_decrypt);
        Self::timed(&self.counters.inner.sym_ns, || {
            self.inner.aead_decrypt(alg, key, ct_tag, nonce, aad)
        })
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        Self::increment(&self.counters.inner.signature_key_gen);
        Self::timed(&self.counters.inner.pubkey_ns, || self.inner.signature_key_gen(alg))
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        Self::increment(&self.counters.inner.verify_signature);
        Self::timed(&self.counters.inner.pubkey_ns, || {
            self.inner.verify_signature(alg, data, pk, signature)
        })
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Self::increment(&self.counters.inner.sign);
        Self::timed(&self.counters.inner.pubkey_ns, || self.inner.sign(alg, data, key))
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        Self::increment(&self.counters.inner.hpke_seal);
        Self::timed(&self.counters.inner.pubkey_ns, || {
            self.inner.hpke_seal(config, pk_r, info, aad, ptxt)
        })
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Self::increment(&self.counters.inner.hpke_open);
        Self::timed(&self.counters.inner.pubkey_ns, || {
            self.inner.hpke_open(config, input, sk_r, info, aad)
        })
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        Self::increment(&self.counters.inner.hpke_setup_sender_and_export);
        Self::timed(&self.counters.inner.pubkey_ns, || {
            self.inner.hpke_setup_sender_and_export(
                config,
                pk_r,
                info,
                exporter_context,
                exporter_length,
            )
        })
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        Self::increment(&self.counters.inner.hpke_setup_receiver_and_export);
        Self::timed(&self.counters.inner.pubkey_ns, || {
            self.inner.hpke_setup_receiver_and_export(
                config,
                enc,
                sk_r,
                info,
                exporter_context,
                exporter_length,
            )
        })
    }

    fn derive_hpke_keypair(
        &self,
        config: HpkeConfig,
        ikm: &[u8],
    ) -> Result<HpkeKeyPair, CryptoError> {
        Self::increment(&self.counters.inner.derive_hpke_keypair);
        Self::timed(&self.counters.inner.pubkey_ns, || self.inner.derive_hpke_keypair(config, ikm))
    }
}

impl<C: OpenMlsRand> OpenMlsRand for InstrumentedCrypto<C> {
    type Error = C::Error;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        Self::increment(&self.counters.inner.random_calls);
        self.counters
            .inner
            .random_bytes
            .fetch_add(N as u64, Ordering::Relaxed);
        self.inner.random_array()
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        Self::increment(&self.counters.inner.random_calls);
        self.counters
            .inner
            .random_bytes
            .fetch_add(len as u64, Ordering::Relaxed);
        self.inner.random_vec(len)
    }
}

/// Default OpenMLS provider with instrumented RustCrypto and normal memory storage.
#[derive(Debug, Default)]
pub struct InstrumentedOpenMlsRustCrypto {
    crypto: InstrumentedCrypto<RustCrypto>,
    key_store: MemoryStorage,
}

impl InstrumentedOpenMlsRustCrypto {
    pub fn counter_handle(&self) -> CounterHandle {
        self.crypto.counter_handle()
    }

    pub fn into_uninstrumented(self) -> OpenMlsRustCrypto {
        OpenMlsRustCrypto::default()
    }
}

impl OpenMlsProvider for InstrumentedOpenMlsRustCrypto {
    type CryptoProvider = InstrumentedCrypto<RustCrypto>;
    type RandProvider = InstrumentedCrypto<RustCrypto>;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.key_store
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
