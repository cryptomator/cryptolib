package org.cryptomator.cryptolib.api;

import org.jspecify.annotations.Nullable;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * The recovery key recipient of a UVF vault: a P-384 EC key pair, or only its public key if the private key is held elsewhere (e.g. by Cryptomator Hub for a vault owner).
 * <p>
 * Instances are plain holders for {@link UvfUnlockedVault#create(SecureRandom, UvfKeyEncryptionKey, UvfRecoveryKey)} and {@link UvfUnlockedVault#setRecoveryKey(UvfRecoveryKey)}.
 * Only a vault that knows the private key can encode it as {@link UnlockedVault#serializedRecoveryKey() recovery key words}.
 */
public final class UvfRecoveryKey {

	private static final String CURVE = "secp384r1";

	private final ECPublicKey publicKey;
	private final @Nullable ECPrivateKey privateKey;

	private UvfRecoveryKey(ECPublicKey publicKey, @Nullable ECPrivateKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}

	/**
	 * Generates a fresh P-384 key pair.
	 *
	 * @param csprng A cryptographically secure random number generator
	 * @return The recovery key
	 */
	public static UvfRecoveryKey generate(SecureRandom csprng) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec(CURVE), csprng);
			return of(generator.generateKeyPair());
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new IllegalStateException("P-384 not supported by this JVM", e);
		}
	}

	/**
	 * @param keyPair A P-384 EC key pair
	 * @return The recovery key
	 * @throws IllegalArgumentException If the pair is not a P-384 EC key pair
	 */
	public static UvfRecoveryKey of(KeyPair keyPair) {
		if (!(keyPair.getPublic() instanceof ECPublicKey && keyPair.getPrivate() instanceof ECPrivateKey)) {
			throw new IllegalArgumentException("Not an EC key pair");
		}
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		if (!isP384(publicKey)) {
			throw new IllegalArgumentException("Not a P-384 key pair");
		}
		return new UvfRecoveryKey(publicKey, (ECPrivateKey) keyPair.getPrivate());
	}

	/**
	 * @param publicKey The public key (P-256, P-384 or P-521) whose private counterpart {@link UvfLockedVault#recover(ECPrivateKey, SecureRandom) recovers} the vault
	 * @return The recovery key, without private part
	 */
	public static UvfRecoveryKey of(ECPublicKey publicKey) {
		return new UvfRecoveryKey(publicKey, null);
	}

	// the curve is identified by its order, which the JDK's ECParameterSpec exposes without naming the curve
	private static boolean isP384(ECPublicKey key) {
		return key.getParams().getOrder().bitLength() == 384;
	}

	public ECPublicKey publicKey() {
		return publicKey;
	}

	/**
	 * @return The private key, or {@code null} if only the public key is known
	 */
	public @Nullable ECPrivateKey privateKey() {
		return privateKey;
	}

}
