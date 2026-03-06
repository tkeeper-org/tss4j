import org.exploit.gmp.BigInt;
import org.exploit.secp256k1.Secp256k1CurveParams;
import org.exploit.secp256k1.Secp256k1PointOps;
import org.exploit.tss.TSS;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

public class Secp256k1PointOpsTest {
    private static final BigInt N;

    private static final BigInt K1;
    private static final BigInt K2;

    private static final Secp256k1PointOps INF;
    private static final Secp256k1CurveParams CURVE;
    static {
        TSS.loadLibraries();

        N = Secp256k1CurveParams.CURVE_ORDER;
        INF = Secp256k1PointOps.INFINITY;
        K1 = new BigInt("123456789", 10);
        K2 = new BigInt("987654321", 10);
        CURVE = new Secp256k1CurveParams();
    }

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] G_COMPRESSED = HEX.parseHex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");

    @Test @DisplayName("baseMul(1) equals canonical generator")
    void testBaseMulOne() {
        var g = Secp256k1PointOps.baseMul(BigInt.ONE);
        assertArrayEquals(G_COMPRESSED, g.encode(true));
    }

    @Test @DisplayName("encode(true) → parse → equals(original)")
    void testEncodeRoundtrip() {
        var p = Secp256k1PointOps.baseMul(K1);
        var copy = Secp256k1PointOps.parse(p.encode(true));
        assertEquals(p, copy);
        assertEquals(33, p.encode(true).length);
        assertEquals(65, p.encode(false).length);
    }

    @Test @DisplayName("P + Q − Q = P")
    void testAddAndSubConsistency() {
        var P = Secp256k1PointOps.baseMul(K1);
        var Q = Secp256k1PointOps.baseMul(K2);
        var R = P.add(Q).sub(Q);
        assertEquals(P, R);
    }

    @Test @DisplayName("P + 0 = P and 0 + P = P")
    void testIdentityAdd() {
        var P = Secp256k1PointOps.baseMul(K1);
        assertEquals(P, P.add(INF));
        assertEquals(P, INF.add(P));
    }

    @Test @DisplayName("P − P = 0 (infinity)")
    void testSubSelfGivesInfinity() {
        var P = Secp256k1PointOps.baseMul(K1);
        assertEquals(INF, P.sub(P));
        assertArrayEquals(new byte[33], INF.encode(true));
    }

    @Test @DisplayName("Addition is commutative")
    void testAddCommutative() {
        var P = Secp256k1PointOps.baseMul(K1);
        var Q = Secp256k1PointOps.baseMul(K2);
        assertEquals(P.add(Q), Q.add(P));
    }

    @Test @DisplayName("Addition is associative for three points")
    void testAddAssociative() {
        var P = Secp256k1PointOps.baseMul(K1);
        var Q = Secp256k1PointOps.baseMul(K2);
        var R = Secp256k1PointOps.baseMul(K1.add(K2).mod(N));
        assertEquals(P.add(Q).add(R), P.add(Q.add(R)));
    }

    @Test @DisplayName("Scalar multiplication property: (k1·G)·k2 == (k1·k2 mod n)·G")
    void testScalarMultiplication() {
        var left  = Secp256k1PointOps.baseMul(K1).mul(K2);
        var right = Secp256k1PointOps.baseMul(K1.multiply(K2).mod(N));
        assertEquals(right, left);
    }

    @Test @DisplayName("Multiplying by zero gives infinity")
    void testMulZero() {
        var any = Secp256k1PointOps.baseMul(K1);
        assertEquals(INF, any.mul(BigInt.ZERO));
    }

    @Test @DisplayName("Multiplying by one is identity")
    void testMulOne() {
        var P = Secp256k1PointOps.baseMul(K1);
        assertEquals(P, P.mul(BigInt.ONE));
    }

    @Test @DisplayName("Multiplying by curve order gives infinity")
    void testMulOrder() {
        var G = Secp256k1PointOps.baseMul(BigInt.ONE);
        assertEquals(INF, G.mul(N));
    }

    @Test @DisplayName("Multiplying by order+1 gives generator")
    void testMulOrderPlusOne() {
        var G = Secp256k1PointOps.baseMul(BigInt.ONE);
        var result = G.mul(N.add(BigInt.ONE));
        assertEquals(G, result);
    }

    @Test @DisplayName("Doubling equals add(P, P) and mul(2)")
    void testDouble() {
        var P = Secp256k1PointOps.baseMul(K1);
        assertEquals(P.add(P), P.dbl());
        assertEquals(P.mul(new BigInt("2", 10)), P.dbl());
    }

    @Test @DisplayName("Negation is its own inverse")
    void testNegateTwice() {
        var P = Secp256k1PointOps.baseMul(K1);
        assertEquals(P, P.negate().negate());
    }

    @Test @DisplayName("isValid(): real point true, infinity false, random false")
    void testIsValid() {
        var P = Secp256k1PointOps.baseMul(K1);
        assertTrue(P.isValid());
        assertFalse(INF.isValid());

        byte[] rand = new byte[33];
        new java.security.SecureRandom().nextBytes(rand);
        assertFalse(Secp256k1PointOps.fromBytes(rand).isValid());
    }

    @Test @DisplayName("equals/hashCode consistency")
    void testEqualsHashCode() {
        var P1 = Secp256k1PointOps.baseMul(K1);
        var P2 = Secp256k1PointOps.baseMul(K1);
        assertEquals(P1, P2);
        assertEquals(P1.hashCode(), P2.hashCode());

        var Q = Secp256k1PointOps.baseMul(K2);
        assertNotEquals(P1, Q);
    }

    @Test @DisplayName("parse with wrong length throws on encode(false)")
    void testInvalidLengthParsing() {
        var invalid = new byte[10];
        assertThrows(IllegalArgumentException.class, () -> {
            Secp256k1PointOps.parse(invalid).encode(false);
        });
    }

    @Test @DisplayName("G.x and G.y are equal to their coordinates")
    void testAffineCoordinatesOfGenerator() {
        var G = Secp256k1PointOps.baseMul(BigInt.ONE);
        assertEquals(new BigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16), G.getAffineX());
        assertEquals(new BigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16), G.getAffineY());
    }

    @Test
    void testAffineAfterMul() {
        var P = Secp256k1PointOps.baseMul(new BigInt("123456789"));

        assertTrue(P.getAffineX().signum() > 0);
        assertTrue(P.getAffineY().signum() > 0);
    }

    @Test @DisplayName("Infinity point has no coordinates")
    void testAffineInfinity() {
        assertThrows(IllegalStateException.class,
                Secp256k1PointOps.INFINITY::getAffineX);
    }

    @Test @DisplayName("createPoint(G.x, G.y) recreates canonical generator")
    void testCreatePointGeneratorFromCoords() {
        var G = Secp256k1PointOps.baseMul(BigInt.ONE);

        var rebuilt = CURVE.createPoint(G.getAffineX(), G.getAffineY());

        assertEquals(G, rebuilt);
        assertTrue(rebuilt.isValid());
        assertArrayEquals(G.encode(true), rebuilt.encode(true));
    }

    @Test @DisplayName("createPoint(P.x, P.y) recreates arbitrary point")
    void testCreatePointRoundtripFromAffine() {
        var P = Secp256k1PointOps.baseMul(K1);

        var rebuilt = CURVE.createPoint(P.getAffineX(), P.getAffineY());

        assertEquals(P, rebuilt);
        assertTrue(rebuilt.isValid());
        assertArrayEquals(P.encode(true), rebuilt.encode(true));
    }

    @Test @DisplayName("createPoint(x, p - y) recreates negated point (same x, opposite y)")
    void testCreatePointWithOppositeYGivesNegation() {
        var P = Secp256k1PointOps.baseMul(K1);

        var x = P.getAffineX();
        var y = P.getAffineY();

        var p = Secp256k1CurveParams.FIELD_P;
        var yNeg = p.subtract(y).mod(p);

        var rebuiltNeg = CURVE.createPoint(x, yNeg);

        assertEquals(P.negate(), rebuiltNeg);
        assertTrue(rebuiltNeg.isValid());
    }
}