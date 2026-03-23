# Ed25519

JNA wrappers over [libsodium](https://doc.libsodium.org/) for Ed25519 curve operations and signing. Native library bundled via tss4j natives.

## Point Arithmetic

`Ed25519PointOps` stores points in libsodium's 32-byte compressed encoding (little-endian y with sign bit in MSB). All group operations delegate to `crypto_core_ed25519_*` — constant-time where libsodium guarantees it.

Two scalar multiplication modes:

- `mulUnclamped` / `baseMulUnclamped` — raw scalar mod order, for protocol-level arithmetic (FROST, DKG, DLEQ)
- `mulClamped` / `baseMulClamped` — clamps scalar per RFC 8032 §5.1.5, for Diffie-Hellman key exchange

## Signing

`Ed25519` exposes two signing modes over libsodium's `crypto_sign_ed25519_*`:

- `signDetached` / `verifyDetached` — 64-byte detached signature
- `sign` / `open` — prepended format (`sig ‖ message`)

Keys are seed-based: `generateKeyPair()` samples a 32-byte seed via `randombytes_buf`; `fromSeed()` is deterministic. The full 64-byte libsodium secret key (`seed ‖ pk`) is used internally for signing but never exposed — `RawEd25519KeyPair` surfaces only the seed and public key.

## Side Channels

libsodium provides constant-time scalar mul and signing. Java layer touches only serialized bytes and public values. Protocol-level scalar arithmetic (`BigInt` / GMP) is variable-time — acceptable in threshold model where shares are distributed.

## Test Coverage

- **`Ed25519Test`**: key generation, seed determinism, detached sign/verify, full sign/open, wrong-key rejection
- **`Ed25519PointTest`**: group axioms (commutativity, add/sub reversibility), doubling vs mul-by-2, encode/decode roundtrip, identity element (`P - P`, `0 * B`), negate involution, `P * k * k⁻¹ = P` in prime-order subgroup, clamped mul validity, invalid point rejection
- **`FrostEd25519CipherSuiteRfcTest`**: RFC 9591 §E.1 vectors (nonces, binding factors, sig shares, final signature)