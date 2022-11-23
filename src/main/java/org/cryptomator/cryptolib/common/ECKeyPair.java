package org.cryptomator.cryptolib.common;

import com.google.common.base.Preconditions;

import javax.security.auth.Destroyable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.Objects;

public class ECKeyPair implements Destroyable {

	private static final String INVALID_KEY_ERROR = "Invalid EC Key";

	private final KeyPair keyPair;
	private boolean destroyed;

	ECKeyPair(KeyPair keyPair, ECParameterSpec curveParams) {
		Preconditions.checkArgument(keyPair.getPrivate() instanceof ECPrivateKey);
		Preconditions.checkArgument(keyPair.getPublic() instanceof ECPublicKey);
		this.keyPair = verify(keyPair, curveParams);
	}

	public KeyPair keyPair() {
		return keyPair;
	}

	public ECPrivateKey getPrivate() {
		Preconditions.checkState(!destroyed);
		assert keyPair.getPrivate() instanceof ECPrivateKey;
		return (ECPrivateKey) keyPair.getPrivate();
	}

	public ECPublicKey getPublic() {
		Preconditions.checkState(!destroyed);
		assert keyPair.getPublic() instanceof ECPublicKey;
		return (ECPublicKey) keyPair.getPublic();
	}

	// validations taken from https://neilmadden.blog/2017/05/17/so-how-do-you-validate-nist-ecdh-public-keys/
	private static KeyPair verify(KeyPair keyPair, ECParameterSpec curveParams) {
		PublicKey pk = keyPair.getPublic();
		Preconditions.checkArgument(pk instanceof ECPublicKey, INVALID_KEY_ERROR);
		Preconditions.checkArgument(curveParams.getCofactor() == 1, "Verifying points on curves with cofactor not supported"); // see "Step 4" in linked post
		ECPublicKey publicKey = (ECPublicKey) pk;
		EllipticCurve curve = curveParams.getCurve();

		// Step 1: Verify public key is not point at infinity.
		Preconditions.checkArgument(!ECPoint.POINT_INFINITY.equals(publicKey.getW()), INVALID_KEY_ERROR);

		final BigInteger x = publicKey.getW().getAffineX();
		final BigInteger y = publicKey.getW().getAffineY();
		final BigInteger p = ((ECFieldFp) curve.getField()).getP();

		// Step 2: Verify x and y are in range [0,p-1]
		Preconditions.checkArgument(x.compareTo(BigInteger.ZERO) >= 0 && x.compareTo(p) < 0, INVALID_KEY_ERROR);
		Preconditions.checkArgument(y.compareTo(BigInteger.ZERO) >= 0 && y.compareTo(p) < 0, INVALID_KEY_ERROR);

		// Step 3: Verify that y^2 == x^3 + ax + b (mod p)
		final BigInteger a = curve.getA();
		final BigInteger b = curve.getB();
		final BigInteger ySquared = y.modPow(BigInteger.valueOf(2), p);
		final BigInteger xCubedPlusAXPlusB = x.modPow(BigInteger.valueOf(3), p).add(a.multiply(x)).add(b).mod(p);
		Preconditions.checkArgument(ySquared.equals(xCubedPlusAXPlusB), INVALID_KEY_ERROR);

		return keyPair;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	@Override
	public void destroy() {
		Destroyables.destroySilently(keyPair.getPrivate());
		destroyed = true;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		ECKeyPair that = (ECKeyPair) o;
		return MessageDigest.isEqual(this.getPublic().getEncoded(), that.getPublic().getEncoded());
	}

	@Override
	public int hashCode() {
		int result = Objects.hash(keyPair.getPublic().getAlgorithm());
		result = 31 * result + Arrays.hashCode(keyPair.getPublic().getEncoded());
		return result;
	}
}
