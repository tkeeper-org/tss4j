# Threshold ECIES (Verifiable Threshold ElGamal Decryption)

Implementation of **(t, n) threshold ECIES**: ElGamal KEM with AEAD symmetric layer and verifiable partial decryption via **DLEQ proofs**. Encryption is non-interactive (standard ECIES); decryption requires cooperation of at least `t` out of `n` participants.

## Supported curves

Any Weierstrass curve implementing `WeierstrassPointOps<P>`. Available configurations:

| Curve             | Class               |
|-------------------|---------------------|
| secp256k1         | `Secp256k1PointOps` |
| secp256r1 (P-256) | `Secp256r1PointOps` |

## Supported symmetric ciphers

| Cipher                    | Key size | Tag size | Notes                                      |
|---------------------------|----------|----------|--------------------------------------------|
| `AesGcmCipher`            | 256 bit  | 128 bit  | Standard AES-256-GCM                       |
| `ChaCha20Poly1305Cipher`  | 256 bit  | 128 bit  | Preferred on platforms without AES-NI      |

## Protocol flow

```
Encryption       Encryptor picks ephemeral r ← Zq,
                 computes R = [r]G, S = [r]PK,
                 derives (kEnc, IV) = HKDF(S, R, curveId, cipherId),
                 outputs CipherText(version, R, c, tag).

Partial          Each participant i computes:
Decryption         dᵢ = [skᵢ]R
                 Attaches DLEQ proof:proves discrete log equality:
                   dᵢ = [skᵢ]R  ∧  Yᵢ = [skᵢ]G
                 without revealing skᵢ.

Combination      Coordinator collects ≥ t partial decrypts,
                 verifies each DLEQ proof:rejects on failure (IdentifiableAbortException),
                 reconstructs shared secret via Lagrange interpolation:
                   S = Σ λᵢ·dᵢ = [sk]R
                 derives (kEnc, IV) = HKDF(S, R, curveId, cipherId),
                 decrypts (c, tag) → plaintext.
```

DLEQ proofs prevent malicious participants from submitting invalid `dᵢ` to corrupt decryption or bias the reconstructed secret. Aborts are **identifiable**, the faulty participant index is exposed.
> **Important:** `Yᵢ` (participant public key share) must be derived from the DKG transcript or VSS commitments:never accepted from the network alongside the partial decrypt. A `Yᵢ` arriving with the `PartialDecrypt` message is untrusted and must be verified against an authenticated source established at keygen.

## Key derivation

HKDF-SHA-384 with a fixed salt and structured info block. Output is 44 bytes: 32-byte encryption key + 12-byte nonce.

**Salt:** `TKeeper-ECIES-HKDF-SHA384-v1` (ASCII, fixed)

**Info encoding**:each field serialized as `[len: 2 bytes BE][value][0x00]`:

```
"TKeeper-ECIES-v1" ‖ curve_id ‖ cipher_id ‖ "key+nonce" ‖ R ‖ aad
```

Two KDF modes are supported for backward compatibility:

| Version           | IKM     | Salt  | Info       | Output   | Notes                            |
|-------------------|---------|-------|------------|----------|----------------------------------|
| `VERSION_V1`      | `S`     | fixed | structured | 44 bytes | Current                          |
| `VERSION_LEGACY`  | `S ‖ R` | none  | none       | 64 bytes | Deprecated, backward compat only |

Legacy mode has no domain separation and concatenates `S‖R` directly as IKM.

## Tests

### End-to-end threshold decryption

Full flow: keygen → share split → encrypt → partial decrypts → DLEQ verify → combine → plaintext. Both test cases run with `(t=2, n=4)` on secp256k1, parameterized over both symmetric ciphers:

- **`ThresholdECIESTest#endToEnd`**:standard `VERSION_V1` ciphertexts
- **`ThresholdECIESTest#decryptsLegacyCipherText`**:backward compat with `VERSION_LEGACY` ciphertexts