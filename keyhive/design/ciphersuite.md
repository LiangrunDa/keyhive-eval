# Cipher Suite

| Feature           | Algorithm                 |
|-------------------|---------------------------|
| Hash              | BLAKE3                    |
| Symmetric Crypto  | [XChaCha20-Poly1305]      |
| Asymmetric Crypto | Curve25519, EdDSA, X25519 |

### Key Commitment & Misuse Resistant Nonces

> [!CAUTION]
> This simple-looking mechanism needs further careful review and scrutiny

XChaCha uses a 24-byte nonce, which makes use of a random nonce safer than ChaCha's 64-bit nonce. Unfortunately this is not automatically key nor message committing; [encryptment] is not provided out of the box.

Under the assumption that BLAKE3 is sufficiently fast[^blake3-perf], we use Keyed BLAKE3 as a MAC.

[^blake3-perf]: https://github.com/BLAKE3-team/BLAKE3/raw/master/media/speed.svg

To help prevent nonce misuse, including both the entire payload (including causal links), cryptographically random 32-byte ChaCha key, and a domain separator guarantees a unique nonce per payload. The only way to get the same nonce is to use the exact same payload: this prevents nonce reuse with the same key across multiple payloads, and the domain separator prevents it across documents.

This strategy also commits to a specific key (and redundantly commits to the message). On one hand, it would be nice to be able to validate the key prior to decryption (and thus saving the work of decrypting a malicious payload in the first place), the reuse resistance includes all three.

```
┌───────────────────────────────────────────────────────────────────────┐
│                           BLAKE3 Keyed Hash                           │
│ ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐                                    │
│         Domain Separator                                              │
│ │┌───────────────┬──────────────┐│┌──────────────┐┌─────────────────┐ │
│  │ Automerge Tag │ Document ID  │ │  ChaCha Key  ││ Cleartext Hash  │ │
│ ││ (Magic Bytes) │ (Public Key) │││              ││    (BLAKE3)     │ │
│  └───────────────┴──────────────┘ └──────────────┘└─────────────────┘ │
│ └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘                                    │
└───────────────────────────────────────────────────────────────────────┘
```

Note that to avoid allocating space for the entire payload in the nonce preimage (on creation and validation), we first hash the content.

(Keyed) BLAKE3 by default produces 32-bytes of output. While we could keep this entire value as the nonce, to conform to XChaCha20 we truncate it to 24 bytes (196-bits).

## Sub-Protocols

| Feature                  | Algorithm                                                                             |
|--------------------------|---------------------------------------------------------------------------------------|
| Group Definition         | Capability Graphs                                                                     |
| Read Group Key Agreement | BeeKEM (Continuous Group Key Agreement)                                               |
| Read Access Revocation   | BeeKEM's in-built PCS mechanism                                                       |
| Transitive Read Access   | BeeKEM + Capabilities                                                                 |
| Granular Edit Access     | Modified (partition tolerant) OCap, predicate attenuation                             |
| Edit Revocation          | Causality locking, backdating detection, default to "whiteout" (skip materialization) |

<!-- External Links -->
[encryptment]: https://eprint.iacr.org/2019/016.pdf
