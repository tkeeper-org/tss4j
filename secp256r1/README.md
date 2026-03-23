# secp256r1 (NIST P-256)

Pure-Java implementation of the P-256 elliptic curve for threshold signature protocols (GG20, FROST). Point Ops codebase is derived from [Bouncy Castle](https://bouncycastle.org)

## Field Arithmetic

`Secp256R1Field` operates on 256-bit integers represented as `int[8]` in little-endian limb order. Ported from Bouncy Castle's `SecP256R1Field` / `Nat256` with the P-256 NIST fast-reduction, with only change that the codebase uses our GMP [BigInt](../bigint) realization instead of Java BigInteger.

## Point Operations

Jacobian coordinates `(X, Y, Z)` internally. Affine conversion (`normalize()`) only on encode/compare.

- `add()` / `dbl()`: ported from BC `SecP256R1Point`, a=-3 doubling optimisation
- `mul()`: Montgomery ladder, 256 iterations regardless of scalar value.
- `sub()` / `negate()`: delegated to `add(negate())`
- `encode()` / `fromBytes()` / `parse()`: SEC1 compressed (33 bytes) and uncompressed (65 bytes)

## Generator H for Pedersen Commitments
NUMS second generator for Pedersen commitments:

```
H = liftX(SHA-256( G_uncompressed ), even_y)
```

Which is identical to:
```
02698bea63dc44a344663ff1429aea10842df27b6b991ef25866b2c6c02cdcc5be
```

## ECDSA

`Secp256r1.signRecoverable()` produces 65-byte compact signatures (`r(32) || s(32) || recId(1)`) with low-s normalisation (BIP-62 / EIP-2 style). Nonce is random (not RFC 6979 deterministic).

`Secp256r1.verify()` does standard ECDSA verification: `u1·G + u2·Q`, check `x mod n == r`.

## FROST (RFC 9591)

`FrostSecp256r1Sha256V1CipherSuite` implements `FROST-P256-SHA256-v1` per [RFC 9591 §6.4](https://www.rfc-editor.org/rfc/rfc9591#section-6.4):

- H1/H2/H3: `hash_to_field` via `expand_message_xmd` (SHA-256, L=48)
- H4/H5: `SHA-256(contextString || tag || m)`
- `contextString = "FROST-P256-SHA256-v1"`

`Secp256r1Frost.schnorrVerify()` verifies FROST Schnorr signatures: `[z]G == R + [c]PK`.

## Side-Channel Properties

| Layer                               | Status                                                                                                  |
|-------------------------------------|---------------------------------------------------------------------------------------------------------|
| Field arithmetic (`Secp256R1Field`) | Effectively constant-time with carry-dependent branches only                                            |
| Point operations (`add`/`dbl`)      | Data-dependent branches on point structure (Z==1), not on scalars                                       |
| Scalar multiplication (`mul`)       | Montgomery ladder, fixed 256 iterations. Branch on bit value observable via μarch side channels in Java |

For threshold protocols (GG20/FROST) where shares are distributed across separate trust domains, this is expected to be sufficient in our threat model.

## Test Coverage

- `Secp256r1Test`: field arithmetic, point ops, ECDSA sign/verify, known vectors (NIST 2G, RFC 6979 key)

## Additional License

While tss4j is under Apache 2.0 License, field arithmetic and point operations are derived from [Bouncy Castle](https://www.bouncycastle.org/) which is under the MIT License.