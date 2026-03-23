# BigInt

GMP-backed arbitrary-precision integer for cryptographic use. Wraps GNU MP (`libgmp`) via JNA, implements `Destroyable` for explicit zeroization, and exposes constant-time variants of core arithmetic operations.

## Why not `java.math.BigInteger`

`BigInteger` is immutable and doesn't zeroize on GC, key material stays in heap until the GC decides otherwise. `BigInt` lets you call `destroy()` immediately after use, and the `Cleaner` fallback handles the rest if you forget.

## Memory management

Each instance registers a `Cleaner` task on construction that calls `__gmpz_clear` when the object is collected. For security-sensitive values, call `destroy()` explicitly: it runs the cleanup immediately and sets the destroyed flag.

The four constants (`ZERO`, `ONE`, `TWO`, `TEN`) are immortal: `destroy()` is a no-op on them.

## Byte array encoding

Two encoding conventions are supported:

| Method                      | Encoding                                          | Use case                              |
|-----------------------------|---------------------------------------------------|---------------------------------------|
| `toByteArray()`             | Two's complement, big-endian (sign bit preserved) | Compatible with `BigInteger`          |
| `toUnsignedByteArray(size)` | Unsigned big-endian, zero-padded to `size` bytes  | EC scalar / fixed-width serialization |

`toUnsignedByteArray` throws `ArithmeticException` on negative input and `IllegalArgumentException` if the value doesn't fit into `size` bytes.

## Constant-time operations

For use in cryptographic code where timing side-channels matter:

| Method          | Equivalent to | Notes                                                       |
|-----------------|---------------|-------------------------------------------------------------|
| `modPowSec`     | `modPow`      | Requires odd modulus (`mpz_powm_sec` constraint)            |
| `multiplySec`   | `multiply`    | Uses `mpn_sec_mul`                                          |
| `modMulSec`     | `modMul`      | `multiplySec` + `mod`                                       |
| `modInverseSec` | `modInverse`  | Prime modulus → Fermat (`a^(m-2) mod m`); otherwise blinded |

`modInverseSec` blinding: for non-prime moduli, the input is additively blinded with a random factor before `modInverse`, preventing the standard extended-GCD from leaking via branch timing.

## Multi-exponentiation

Simultaneous double-base exponentiation `base1^exp1 · base2^exp2 mod m`:

| Method            | Exponents    | Timing                                                       |
|-------------------|--------------|--------------------------------------------------------------|
| `multiExp2`       | Non-negative | Variable                                                     |
| `multiExp2Sec`    | Non-negative | Constant-time (all 4 bit combos evaluated uniformly)         |
| `multiExp2Signed` | Any sign     | Variable (negates base and flips sign before `multiExp2`)    |

`multiExp2Sec` pre-computes `ab = a·b mod m` and uses a 2-bit index per iteration to avoid conditional branches on exponent bits.

## Tests

- **`BigIntTest`**: arithmetic correctness (add, subtract, multiply, divide, mod, gcd, pow, modPow, modInverse, shifts, signum, byte array encoding)
- Constant-time variants validated against regular counterparts: `modPowSec`, `multiplySec`, `modInverseSec` (20–30 random iterations each)
- Edge cases: division by zero, negative modulus, non-coprime inverse, overflow in `toUnsignedByteArray`, shift by negative, shift beyond size