import org.exploit.ed25519.Ed25519CurveParams;
import org.exploit.ed25519.Ed25519PointOps;
import org.exploit.gmp.BigInt;
import org.exploit.sodium.Sodium;
import org.exploit.tss.TSS;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class Ed25519PointTest {
    private final SecureRandom RANDOM = new SecureRandom();
    private final Ed25519CurveParams CURVE = new Ed25519CurveParams();
    private final BigInt ORDER = CURVE.getCurveOrder();
    private final byte[] IDENTITY_ENCODED = new byte[Sodium.crypto_core_ed25519_BYTES];

    static {
        TSS.loadLibraries();
    }

    {
        IDENTITY_ENCODED[0] = 1;
    }

    @Test
    public void testAddSubtractReversibility() {
        var p = Ed25519PointOps.random();
        var q = Ed25519PointOps.random();
        var r = p.add(q);
        var s = r.sub(q);
        assertEquals(p, s, "(P + Q) - Q should equal P");
    }

    @Test
    public void testAddCommutative() {
        var p = Ed25519PointOps.random();
        var q = Ed25519PointOps.random();
        assertEquals(p.add(q), q.add(p), "Addition should be commutative");
    }

    @Test
    public void testDoublingEqualsMulTwo() {
        var p = Ed25519PointOps.random();
        var dbl = p.dbl();
        var mul2 = p.mul(BigInt.TWO);
        assertEquals(dbl, mul2, "Double should equal multiplication by 2");
    }

    @Test
    public void testMulUnclampedIdentity() {
        var p = Ed25519PointOps.random();
        var oneP = p.mulUnclamped(BigInt.ONE);
        assertEquals(p, oneP, "P * 1 should equal P (unclamped)");
    }

    @Test
    public void testBaseMulUnclamped() {
        var B = Ed25519PointOps.baseMulUnclamped(BigInt.ONE);
        var B2 = Ed25519PointOps.baseMulUnclamped(BigInt.valueOf(2));
        assertEquals(B.add(B), B2, "2 * B should equal B.add(B) (unclamped)");
    }

    @Test
    public void testScalarInverseUnclamped() {
        BigInt rScalar;
        do {
            rScalar = new BigInt(ORDER.bitLength(), RANDOM).mod(ORDER);
        } while (rScalar.signum() == 0);

        var p = Ed25519PointOps.baseMulUnclamped(rScalar);

        BigInt k;
        do {
            k = new BigInt(ORDER.bitLength(), RANDOM).mod(ORDER);
        } while (k.compareTo(BigInt.ONE) < 0);

        System.out.println("K= " + k);
        var inv = k.modInverse(ORDER);
        System.out.println("K MOD INVERSE= " + inv);
        System.out.println("ORDER=" + ORDER);

        var result = p.mulUnclamped(k).mulUnclamped(inv);
        assertEquals(p, result, "P * k * k^{-1} should equal P (for points in the prime-order subgroup)");
    }

    @Test
    public void testSubEqualsAddNegate() {
        var p = Ed25519PointOps.random();
        var q = Ed25519PointOps.random();
        assertEquals(p.sub(q), p.add(q.negate()), "P - Q should equal P + (-Q)");
    }

    @Test
    public void testNegateInvolution() {
        var p = Ed25519PointOps.random();
        assertEquals(p, p.negate().negate(), "Negating twice should return the original point");
    }

    @Test
    public void testNormalizeIdempotent() {
        var p = Ed25519PointOps.random();
        assertEquals(p, p.normalize(), "Normalize should return the same point");
    }

    @Test
    public void testEncodeDecodeConsistency() {
        var p = Ed25519PointOps.random();
        var enc = p.encode(true);
        var decoded = new Ed25519PointOps(enc);
        assertEquals(p, decoded, "Decoding the encoded point should recover the original");
        assertArrayEquals(enc, decoded.encode(false), "Re-encoded bytes should match original encoding");
    }

    @Test
    public void testParseInvalidLength() {
        var buf = new byte[Sodium.crypto_core_ed25519_BYTES - 1];
        assertThrows(IllegalArgumentException.class, () -> Ed25519PointOps.parse(buf), "Invalid length should throw");
    }

    @Test
    public void testInvalidPoint() {
        var buf = new byte[Sodium.crypto_core_ed25519_BYTES];
        assertFalse(Ed25519PointOps.fromBytes(buf).isValid(), "Invalid point should return false");
    }

    @Test
    public void testSubSelfYieldsIdentity() {
        var p = Ed25519PointOps.random();
        var id = p.sub(p);
        assertArrayEquals(IDENTITY_ENCODED, id.encode(false), "P - P should yield identity element");
    }

    @Test
    public void testMulClampedProducesValidPoint() {
        var p = Ed25519PointOps.random();
        var enc = p.mulClamped(BigInt.valueOf(5)).encode(false);
        assertTrue(() -> Ed25519PointOps.parse(enc).isValid(), "Clamped multiplication should yield valid point");
    }

    @Test
    public void testBaseMulClampedProducesValidPoint() {
        var enc = Ed25519PointOps.baseMulClamped(BigInt.valueOf(5)).encode(false);
        assertDoesNotThrow(() -> Ed25519PointOps.parse(enc), "Clamped base multiplication should yield valid point");
    }

    @Test
    public void testSubZeroIdentity() {
        var B = Ed25519PointOps.baseMulUnclamped(BigInt.ZERO);
        assertArrayEquals(IDENTITY_ENCODED, B.encode(false), "0 * B should yield identity element");
    }
}
