package org.cryptomator.cryptolib.common;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;

public class GcmTestHelper {

	private static final Random RNG = new Random(42L);

	/**
	 * Java's default GCM implementation has built-in IV-reuse protection. In order to run certain unit tests,
	 * this needs to be bypassed. The easiest way would be to re-initialize the cipher before running a test.
	 * <p>
	 * This method can be used to init a cipher using randomized key-iv-pairs during test setup and avoid
	 * InvalidAlgorithmParameterExceptions.
	 *
	 * @param cipherInitializer The {@link Cipher#init(int, Key, AlgorithmParameterSpec) cipher.init()} or equivalent method
	 */
	public static void reset(CipherInitializer cipherInitializer) {
		byte[] keyBytes = new byte[16];
		byte[] nonceBytes = new byte[12];
		RNG.nextBytes(keyBytes);
		RNG.nextBytes(nonceBytes);
		SecretKey key = new SecretKeySpec(keyBytes, "AES");
		AlgorithmParameterSpec params = new GCMParameterSpec(96, nonceBytes);
		try {
			cipherInitializer.init(Cipher.ENCRYPT_MODE, key, params);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException("Failed to reset cipher");
		}
	}

	@FunctionalInterface
	public interface CipherInitializer {

		void init(int opmode, SecretKey key, AlgorithmParameterSpec params)
				throws InvalidKeyException, InvalidAlgorithmParameterException;

	}

}
