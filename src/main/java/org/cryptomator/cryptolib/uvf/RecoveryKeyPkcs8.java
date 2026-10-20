package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * PKCS#8 encoding of the P-384 recovery key as produced by Cryptomator Hub (WebCrypto): {@code PrivateKeyInfo} with the {@code ECPrivateKey} carrying the public key but no curve parameters.
 *
 * @implNote All lengths are fixed for P-384 (RFC 5915 pads the private scalar to 48 bytes), so the DER structure is a constant template around the scalar and the uncompressed public point.
 */
final class RecoveryKeyPkcs8 {

	private static final int COORDINATE_LEN = 48;
	// SEQUENCE { INTEGER 0, SEQUENCE { OID id-ecPublicKey, OID secp384r1 }, OCTET STRING { SEQUENCE { INTEGER 1, OCTET STRING(48) ...
	private static final byte[] PREFIX = {0x30, (byte) 0x81, (byte) 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, (byte) 0x81, 0x04, 0x00, 0x22, 0x04, (byte) 0x81, (byte) 0x9e, 0x30, (byte) 0x81, (byte) 0x9b, 0x02, 0x01, 0x01, 0x04, 0x30};
	// ... [1] { BIT STRING(97) 0x04 || x || y } } }
	private static final byte[] INFIX = {(byte) 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04};
	static final int LEN = PREFIX.length + COORDINATE_LEN + INFIX.length + 2 * COORDINATE_LEN;

	private RecoveryKeyPkcs8() {
	}

	/**
	 * @param keyPair A P-384 key with private part
	 * @return The PKCS#8 encoding
	 */
	static byte[] encode(ECKey keyPair) {
		if (!Curve.P_384.equals(keyPair.getCurve())) {
			throw new IllegalArgumentException("Not a P-384 key");
		}
		if (!keyPair.isPrivate()) {
			throw new IllegalArgumentException("Key has no private part");
		}
		byte[] d = keyPair.getD().decode();
		byte[] x = keyPair.getX().decode();
		byte[] y = keyPair.getY().decode();
		assert d.length == COORDINATE_LEN && x.length == COORDINATE_LEN && y.length == COORDINATE_LEN; // nimbus encodes coordinates with the field size
		try {
			return ByteBuffer.allocate(LEN).put(PREFIX).put(d).put(INFIX).put(x).put(y).array();
		} finally {
			Arrays.fill(d, (byte) 0x00);
		}
	}

	/**
	 * @param pkcs8 A PKCS#8 encoded EC private key (with or without embedded public key or curve parameters)
	 * @return The private key
	 * @throws IllegalArgumentException If the bytes are not a P-384 private key
	 */
	static ECPrivateKey decode(byte[] pkcs8) {
		try {
			ECPrivateKey key = (ECPrivateKey) KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
			if (!Curve.P_384.equals(Curve.forECParameterSpec(key.getParams()))) {
				throw new IllegalArgumentException("Not a P-384 key");
			}
			return key;
		} catch (InvalidKeySpecException | ClassCastException e) {
			throw new IllegalArgumentException("Not an EC private key", e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("EC not supported by this JVM", e);
		}
	}

}
