package org.cryptomator.cryptolib.common;

import com.google.common.annotations.VisibleForTesting;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

public class HKDFHelper {

	/**
	 * Derives a key from the given input keying material (IKM) using the HMAC-based Key Derivation Function (HKDF) with the SHA-512 hash function.
	 * @param salt The optional salt (can be an empty byte array)
	 * @param ikm The input keying material
	 * @param info The optional context (can be an empty byte array)
	 * @param length Desired output key length
	 * @return The derived key
	 * @implNote This method uses the Bouncy Castle library for HKDF computation.
	 */
	public static byte[] hkdfSha512(byte[] salt, byte[] ikm, byte[] info, int length) {
		return hkdf(new SHA512Digest(), salt, ikm, info, length);
	}

	@VisibleForTesting static byte[] hkdf(Digest digest, byte[] salt, byte[] ikm, byte[] info, int length) {
		byte[] result = new byte[length];
		DerivationFunction hkdf = new HKDFBytesGenerator(digest);
		hkdf.init(new HKDFParameters(ikm, salt, info));
		hkdf.generateBytes(result, 0, length);
		return result;
	}
}
