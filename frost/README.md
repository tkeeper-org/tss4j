# FROST (Flexible Round-Optimized Schnorr Threshold Signatures)

Implementation of [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591) two-round threshold Schnorr signing protocol with Proof-of-Possession (PoP) commitments with **Taproot** signatures support for secp256k1.

## Supported Curves

- ed25519
- secp256k1
- secp256r1 (P-256)

## Supported Ciphersuites

| Ciphersuite                         | Curve     | Hash    | contextString               |
|-------------------------------------|-----------|---------|-----------------------------|
| `FrostEd25519Sha512V1CipherSuite`   | Ed25519   | SHA-512 | `FROST-ED25519-SHA512-v1`   |
| `FrostSecp256k1Sha256V1CipherSuite` | secp256k1 | SHA-256 | `FROST-secp256k1-SHA256-v1` |
| `FrostSecp256r1Sha256V1CipherSuite` | P-256     | SHA-256 | `FROST-P256-SHA256-v1`      |

All ciphersuites implement `FrostCipherSuite<P>` and are parameterized by point type. Hash functions H1–H5 follow RFC 9591 §6 exactly:

- **H1/H2/H3** (Ed25519): `H(ctx ‖ tag ‖ m)` → little-endian → mod q
- **H1/H2/H3** (secp256k1, P-256): `hash_to_field` via `expand_message_xmd` (SHA-256, L=48)
- **H4/H5** (all): `H(ctx ‖ "msg"/"com" ‖ m)`

## Protocol Flow

Standard RFC 9591 two-round signing with Proof-of-Possession verification on commitment ingestion:

```
Round 1 (Commitment)  Each signer generates (hiding_nonce, binding_nonce),
                      computes commitments D_i = [d_i]G, E_i = [e_i]G,
                      attaches PoP proof (R_pop, σ) over Y_i,
                      broadcasts to all participants.

    PoP verification  On storeCommitment(), each recipient verifies:
                        [σ]G == R_pop + [H(domain ‖ aad ‖ Y_i ‖ R_pop)]·Y_i
                      Rejects with IdentifiableAbortException on failure.

Round 2 (Signing)     Each signer computes signature share:
                        z_i = d_i + e_i·ρ_i + λ_i·sk_i·c
                      Sends z_i to coordinator.

Aggregation           Coordinator sums z = Σz_i, outputs sig = (R, z).
                      Verifies: [z]G == R + [c]PK
```

PoP verification is not part of RFC 9591. It binds each participant's identity to their key share, preventing rogue-key attacks in setups where shares come from DKG rather than a trusted dealer.

> **Important:** In tests, clients pass `Y_i` to each other directly. In production (e.g. [TKeeper](https://github.com/tkeeper-org/tkeeper)), each recipient **must** derive `Y_i` independently from the key generation output (DKG transcript or dealer's VSS commitments). Never trust a `Y_i` that arrives alongside the commitment, it must come from an authenticated source established during keygen.

All components are generic over `P extends PointOps<P>`: curve-specific logic lives entirely in the ciphersuite.

## Signing Schemes

Each `FrostClient` is initialized with a `FrostScheme<P>` that controls signature format, challenge computation, and key/nonce handling. The scheme wraps a ciphersuite (H1–H5) and adds protocol-level logic.

**Default schemes** (RFC 9591 Schnorr, SEC1-compressed R):

| Scheme                 | Curve     | Signature format                  |
|------------------------|-----------|-----------------------------------|
| `FrostEd25519Scheme`   | Ed25519   | 64 bytes (R‖z, RFC 8032 encoding) |
| `FrostSecp256k1Scheme` | secp256k1 | 65 bytes (R_compressed‖z)         |
| `FrostSecp256r1Scheme` | P-256     | 65 bytes (R_compressed‖z)         |

**Bitcoin-specific schemes** (secp256k1 only):

| Scheme               | Description                                                                                                                                                                                                                                                      | Signature format     |
|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------|
| `FrostBIP340Scheme`  | BIP-340 Schnorr: x-only R and PK, even-y normalisation. Challenge uses `BIP0340/challenge` tagged hash. Compatible with Bitcoin Schnorr verification.                                                                                                           | 64 bytes (R_xonly‖s) |
| `FrostTaprootScheme` | BIP-341 Taproot key-path spending. Applies TapTweak (`H("TapTweak" ‖ internal_key ‖ merkle_root)`) to the group public key during signing. Handles even-y normalisation for both internal key and tweaked output key. Initialized with a `merkleRoot` parameter. | 64 bytes (R_xonly‖s) |

BIP-340 and Taproot schemes reuse `FrostSecp256k1Sha256V1CipherSuite` for H1/H3/H4/H5 but override H2 (challenge) with BIP-340 tagged hashing, and adjust nonce/key sign correction to match x-only pubkey semantics.

## Tests

### CipherSuite RFC vectors (per curve)

Full RFC 9591 Appendix E test vectors: nonce generation, binding factor inputs, binding factors, signature shares, final signature verification:

- **`FrostEd25519CipherSuiteRfcTest`**: §E.1 vectors
- **`FrostSecp256k1CipherSuiteRfcTest`**: §E.5 vectors
- **`FrostSecp256r1CipherSuiteRfcTest`**: §E.4 vectors

### End-to-end threshold signing (per curve)

Full protocol execution: keygen → share split → PoP → commitments → signing → aggregation → verify. Each test runs 1000 batch operations per session:

- **`ThresholdEd25519Tests`**
- **`ThresholdFrostSecp256k1Tests`**
- **`ThresholdBIP340SchnorrTests`**
- **`ThresholdTaprootSchnorTests`**
- **`ThresholdSecp256r1Tests`**