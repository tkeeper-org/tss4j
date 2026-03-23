# secp256k1

JNA wrappers over [libsecp256k1](https://github.com/bitcoin-core/secp256k1) for secp256k1 curve operations. Native library bundled via tss4j natives.

## Point Arithmetic

`Secp256k1PointOps` stores compressed SEC1 bytes (33 bytes). Constant-time scalar mul is handled by libsecp256k1 internally.

## Generator H

NUMS second generator for Pedersen commitments:

```
H = liftX(SHA-256(G_uncompressed), odd_y)
```

Which is identical to
```
0350929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0
```

## ECDSA / Schnorr / Taproot

- `signRecoverable()` / `verifyRecoverable()` — compact 65-byte `r‖s‖recId`
- `schnorrSign()` / `schnorrVerify()` — BIP-340
- `taprootSign()` / `taprootVerify()` — BIP-341 key-path with merkle root tweak
- `xonlyFromSecret()` — x-only public key with parity

## Hash-to-Curve

`Secp256k1XmdSha256SSWUROSuite.hashToCurve()` implements the `secp256k1_XMD:SHA-256_SSWU_RO_` suite from [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380). Verified against all five RFC 9380 test vectors.

## Side Channels

Native libsecp256k1 provides constant-time scalar mul and ECDSA signing. Java layer touches only serialized bytes and public values. Protocol-level scalar arithmetic (`BigInt` / GMP) is variable-time — acceptable in threshold model where shares are distributed.

## Test Coverage

- **`Secp256k1PointOpsTest`**: group axioms, scalar mul properties, encode/decode roundtrips, affine coordinates, `createPoint` roundtrips
- **`Secp256k1Test`**: recoverable ECDSA, Schnorr sign/verify, Taproot key-path and script-path, wrong key rejection, xonly consistency
- **`Secp256k1XmdSha256SSWUROSuiteTest`**: RFC 9380 hash-to-curve vectors, determinism, DST separation
- **`FrostSecp256k1CipherSuiteRfcTest`**: RFC 9591 §E.5 vectors (nonces, binding factors, sig shares, prime_order_verify)