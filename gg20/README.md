# GG20 (Gennaro–Goldfeder 2020 Threshold ECDSA)

Threshold t-of-n ECDSA signing based on [Gennaro & Goldfeder 2020](https://eprint.iacr.org/2020/540), hardened with ZK proofs from [CGGMP21/24](https://eprint.iacr.org/2021/060).

One-round online signing with identifiable abort. No trusted dealer required when paired with a DKG protocol.

## Supported Curves

- secp256k1
- secp256r1 (P-256)

## Protocol

Signing runs in two phases:

**Offline (pre-signing).** Each participant generates ephemeral values k_i, γ_i and broadcasts Pedersen commitments to Γ_i = [γ_i]G. Pairwise MtA sub-protocols convert multiplicative shares into additive ones for both k·γ (used for R derivation) and k·w (used for signature share). Delta shares are exchanged and verified against commitments.

**Online.** Given a message hash, each participant computes a partial signature s_i. The coordinator aggregates into (r, s) and verifies before publishing. If verification fails, misbehaving participants are identified through share-level checks.

```
Offline           Each participant i generates k_i, γ_i,
                  computes commitment C_i = Commit(Γ_i, r_i),
                  broadcasts C_i and ZK setup (Paillier pk + proofs) to all.

MtA               For each pair (i, j):
                    initiator encrypts: c_A = Enc_i(k_i)  [or γ_i]
                    respondent evaluates homomorphically, returns c_j with proof
                  Produces additive shares: α_ij + β_ji = k_i · γ_j  (and k_i · w_j)

Offline collect   Participants open Γ_i, exchange delta shares δ_i = k_i·γ_i + Σα + Σβ,
                  verify C_i openings and sigma commitments,
                  reconstruct R = [Σδ_i^{-1}]·[ΣΓ_i].

Online            Each participant computes partial s_i,
                  coordinator aggregates s = Σs_i,
                  outputs sig = (r, s).
```

## MtA Sub-Protocol

Multiplicative-to-Additive conversion uses Paillier homomorphic encryption. The initiator encrypts their value under their own Paillier key and sends c_A = Enc(a_i) along with ZK proofs. The respondent homomorphically evaluates c_j = c_A^{b_j} · Enc(y) and returns the result with a respondent proof.

Two MtA variants are used:

- **MtA(k, γ)**: ephemeral values only, no EC binding required.
- **MtAwc(k, w)**: respondent proves that b_j corresponds to the discrete log of their Lagrange-weighted public key W_j = [λ_j]Y_j via an integrated Schnorr check in the respondent proof.

## Zero-Knowledge Proofs

### Paillier-Blum Modulus Proof 

Proves that the Paillier modulus N is a product of exactly two primes p, q where p ≡ q ≡ 3 (mod 4). Verifier checks J(w, N) = −1 and validates N-th root and fourth-root relations across 64 rounds. Addresses [CVE-2023-33241 (BitForge)](https://www.fireblocks.com/blog/bitforge-fireblocks-researchers-uncover-vulnerabilities-in-over-15-major-wallet-providers) and [CVE-2025-66016](https://eprint.iacr.org/2023/1555) (missing Jacobi check allows proof forgery).

### No Small Factors Proof

Proves that both prime factors of N exceed 2²⁵⁶. Uses Pedersen commitments over an auxiliary RSA modulus (Ring-Pedersen parameters) with ℓ = 256, ε = 16. Based on CGGMP21 §C.5.

### Range Proof

Proves that the plaintext encrypted under Paillier lies within [−q³, q³] without revealing the value. Uses Pedersen commitments over the verifier's Ring-Pedersen setup. Prevents adversarial MtA inputs that would leak key share bits through algebraic relations ([Alpha-Rays](https://eprint.iacr.org/2021/1621)).

### Respondent Proof 

Proves correct homomorphic evaluation: given c_A and the returned c_j, the respondent knows b, y such that c_j = c_A^b · Enc(y). In the MtAwc variant, includes EC-point binding: the proof commits to V = [α]G and the verifier checks [s₁]G = V + [e]W_j, ensuring the respondent used the same b_j that corresponds to their public key share. Uses independent randomness for each Pedersen commitment to preserve hiding.

### Paillier Encryption Proof

Standard sigma protocol proving knowledge of the plaintext and randomness in a Paillier ciphertext. Used as a building block in MtA initiation; does not provide range guarantees on its own.


## Security Parameters

| Parameter                       | Value                         |
|---------------------------------|-------------------------------|
| Paillier modulus                | ≥ 3072 bits (N ≥ q⁸ enforced) |
| Ring-Pedersen auxiliary modulus | ≥ 2048 bits                   |
| Blum proof rounds               | 64                            |
| No small factors ℓ              | 256 bits                      |
| Range proof bound               | q³                            |

## Addressed Vulnerabilities

| Reference      | Description                                                              |
|----------------|--------------------------------------------------------------------------|
| CVE-2023-33241 | BitForge: Paillier key with small factors enables key extraction via MtA |
| CVE-2025-66016 | Missing Jacobi check in Paillier-Blum proof allows proof forgery         |
| Alpha-Rays     | MtA range proof bypass via adversarial k selection                       |

## Test Coverage

### End-to-end signing sessions (per curve)

Full protocol execution: keygen → share split → ZK setup → offline phase → MtA → partial S → aggregation → verify. Each test runs 3 sessions:

- **`GG20Secp256k1SessionTest`**: secp256k1, verified via recoverable ECDSA
- **`GG20Secp256r1SessionTest`**: secp256r1 (P-256), verified via recoverable ECDSA

Both extend `AbstractGG20SessionTest` with a `(t=2, n=4)` configuration.

### Commitment

- **`GG20CommitmentTest`**: Pedersen commitment create/verify, rejection on wrong Γ_i, rejection on wrong r_i

___
These tests are located in the project root, not in this module:

### Paillier

- **`PaillierTest`**: encrypt/decrypt roundtrip, homomorphic addition (`Enc(m1)·Enc(m2)` → `m1+m2`), homomorphic scalar mul (`Enc(m)^k` → `k·m`), large values (4096-bit key, 1280-bit plaintext), rejection of negative and out-of-range messages

### MtA Protocol

- **`MtAProtocolTest`**: core MtA correctness (`α + β = a·b mod q`), initiator range proof generate/verify and tamper rejection, respondent proof generate/verify and tamper rejection, wrong W_j rejection, input validation (null, negative, out-of-range)
- **`CryptoHardeningTest`**: `randomZnStar` coprimality, `Bytes.encode` length-prefix collision resistance, full initiator message verification (range proof + BiPrime proof)

### ZK Proofs

- **`BiPrimeProofTests`**: 64 random 3072-bit Paillier keys prove and verify; rejection on wrong context, wrong modulus, tampered aBits / xs / w (64 repeated runs)
- **`FacProofTest`**: NoSmallFactors proof passes on 3072-bit keys (64 repeated runs); rejection on tampered commitment A, wrong context (64 repeated runs)
- **`DleqProofTest`**: DLEQ proof verifies for random scalars (64 repeated runs); tamper rejection on r, A1, A2; edge cases (±1 scalars)
- **`ChaumPedersenProofTest`**: Chaum-Pedersen proof over (G, H) verifies (64 repeated runs); tamper rejection on r, s, A; edge cases (±1 scalars)
- **`PaillierZKProofValidatorTest`**: sigma proof for Paillier ciphertext knowledge, valid and tampered response

### Key Extraction Hardening

- **`KeyExtractionHardeningTests`**: BiPrime rejects mismatched public key N; generator rejects non-Blum modulus; MtA rejects N < q⁸; range proof context binding and ciphertext binding; NoSmallFactors rejects keys < 2048 bits and forged commitments; range proof s1 bound check; respondent proof context binding, c_j tamper, non-unit c_i, s1/t1 range checks