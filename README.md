![](assets/tss4j.png)
# MPC Threshold Schemes in Java

Java library implementing multi-party ECDSA (GG20), Schnorr (FROST), threshold ECIES, and the ZK building blocks they depend on. Native performance via JNA bindings to libgmp and libsodium.

This is the backbone library of [TKeeper (Threshold Key Management System)](https://github.com/tkeeper-org/tkeeper)

## Modules

| Module            | Purpose                                                        |
|-------------------|----------------------------------------------------------------|
| `frost`           | FROST (RFC 9591) t-of-n Schnorr threshold signatures           |
| `frost-secp256k1` | secp256k1 FROST schemes: default, BIP-340, Taproot (BIP-341)   |
| `frost-ed25519`   | Ed25519 FROST scheme                                           |
| `gg20`            | GG20 t-of-n threshold ECDSA with Paillier/MtA and ZK hardening |
| `ecies`           | Threshold ElGamal KEM with verifiable partial decryption       |
| `ed25519`         | JNA wrappers over libsodium: Ed25519 point ops and signing     |
| `secp256k1`       | JNA wrappers over libsecp256k1: point ops, ECDSA, Schnorr      |
| `secp256r1`       | Pure Java P-256 curve implementation based on Bouncy Castle    |
| `bigint`          | JNA bindings to libgmp: arbitrary-precision integers, CT ops   |
| `sodium`          | Low-level libsodium JNA bindings (used by ed25519 module)      |

## Protocols

### FROST: Threshold Schnorr (RFC 9591)

Two-round Schnorr threshold signing with Proof-of-Possession commitments. Each participant proves knowledge of their key share before any signing begins, preventing rogue-key attacks in DKG-based setups.

Supported ciphersuites:

| Scheme                 | Curve     | Notes                                  |
|------------------------|-----------|----------------------------------------|
| `FrostEd25519Scheme`   | Ed25519   | RFC 8032-compatible output             |
| `FrostSecp256k1Scheme` | secp256k1 | SEC1-compressed R                      |
| `FrostBIP340Scheme`    | secp256k1 | BIP-340 Schnorr, x-only                |
| `FrostTaprootScheme`   | secp256k1 | BIP-341 Taproot key-path with TapTweak |
| `FrostSecp256r1Scheme` | P-256     | SEC1-compressed R                      |

### GG20: Threshold ECDSA

One-round online threshold ECDSA with identifiable abort. Hardened against CVE-2023-33241 (BitForge), CVE-2025-66016, and Alpha-Rays via the full CGGMP21/24 ZK proof suite:

- **Π_{mod}**: Paillier-Blum modulus proof (Jacobi symbol check included)
- **Π_{fac}**: No small factors proof (primes > 2²⁵⁶)
- **Π_{range}**: Range proof for MtA plaintexts (bound q³)
- **Π_{resp}**: Respondent proof with EC-point binding (MtAwc)
- **Π_{enc}**: Paillier encryption knowledge proof

Supported curves: secp256k1, secp256r1 (P-256).

### Threshold ECIES: Verifiable Threshold Decryption

ElGamal KEM with AEAD symmetric layer. Encryption is non-interactive; decryption requires ≥ t participants, each producing a partial decrypt with a DLEQ proof. Coordinator verifies all proofs before combining via Lagrange interpolation. Faulty participants identified via `IdentifiableAbortException`.

Supported ciphers: AES-256-GCM, ChaCha20-Poly1305. KDF: HKDF-SHA-384 with domain separation.

## Setup

### Requirements

- JDK 17+
- Native libraries bundled as platform classifiers:

```groovy
implementation("org.exploit:tss4j-natives:1.0.0:linux-amd64@jar")
implementation("org.exploit:tss4j-natives:1.0.0:macos-aarch64@jar")
implementation("org.exploit:tss4j-natives:1.0.0:windows-amd64@jar")
```

Load them before any cryptographic operation:

```java
TSS.loadLibraries();
```

RNG: ZK transcripts use the built-in `ZKRandom` (backed by `SecureRandom.getInstanceStrong()`).

## Security

See [Threat Model](THREAT_MODEL.md) for the full adversary model, threat catalog, ZK proof inventory, and addressed CVEs.

## License

tss4j is licensed under [Apache License 2.0](LICENSE)