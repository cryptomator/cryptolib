package org.cryptomator.cryptolib.ecies;

import org.cryptomator.cryptolib.common.Destroyables;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

public class ECIntegratedEncryptionScheme {

	/**
	 * The ECIES used in Cryptomator Hub:
	 * <ul>
	 *     <li>To be used with {@link org.cryptomator.cryptolib.common.P384KeyPair P-384 EC keys}</li>
	 *     <li>Use ANSI X9.63 KDF with SHA-256 to derive a 352 bit shared secret</li>
	 *     <li>Cut shared secret into 256 bit key + 96 bit nonce used for AES-GCM to encrypt/decrypt</li>
	 * </ul>
	 */
	public static ECIntegratedEncryptionScheme HUB = new ECIntegratedEncryptionScheme(AuthenticatedEncryption.GCM_WITH_SECRET_NONCE, KeyDerivationFunction.ANSI_X963_SHA256_KDF);

	private final AuthenticatedEncryption ae;
	private final KeyDerivationFunction kdf;

	public ECIntegratedEncryptionScheme(AuthenticatedEncryption ae, KeyDerivationFunction kdf) {
		this.ae = ae;
		this.kdf = kdf;
	}

	public EncryptedMessage encrypt(KeyPairGenerator ephKeyGen, ECPublicKey receiverPublicKey, byte[] plaintext) {
		KeyPair ephKeyPair = ephKeyGen.generateKeyPair();
		try {
			if (ephKeyPair.getPrivate() instanceof ECPrivateKey) {
				assert ephKeyPair.getPublic() instanceof ECPublicKey;
				byte[] ciphertext = encrypt((ECPrivateKey) ephKeyPair.getPrivate(), receiverPublicKey, plaintext);
				return new EncryptedMessage((ECPublicKey) ephKeyPair.getPublic(), ciphertext);
			} else {
				throw new IllegalArgumentException("key generator didn't create EC key pair");
			}
		} finally {
			Destroyables.destroySilently(ephKeyPair.getPrivate());
		}
	}

	public byte[] decrypt(ECPrivateKey receiverPrivateKey, EncryptedMessage encryptedMessage) throws AEADBadTagException {
		return decrypt(receiverPrivateKey, encryptedMessage.getEphPublicKey(), encryptedMessage.getCiphertext());
	}

	// visible for testing
	byte[] encrypt(ECPrivateKey ephPrivateKey, ECPublicKey receiverPublicKey, byte[] plaintext) {
		byte[] secret = ecdhAndKdf(ephPrivateKey, receiverPublicKey, ae.requiredSecretBytes());
		return ae.encrypt(secret, plaintext);
	}

	// visible for testing
	byte[] decrypt(ECPrivateKey receiverPrivateKey, ECPublicKey ephPublicKey, byte[] plaintext) throws AEADBadTagException {
		byte[] secret = ecdhAndKdf(receiverPrivateKey, ephPublicKey, ae.requiredSecretBytes());
		return ae.decrypt(secret, plaintext);
	}

	private byte[] ecdhAndKdf(ECPrivateKey privateKey, ECPublicKey publicKey, int numBytes) {
		byte[] sharedSecret = new byte[0];
		try {
			KeyAgreement keyAgreement = createKeyAgreement();
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(publicKey, true);
			sharedSecret = keyAgreement.generateSecret();
			return kdf.deriveKey(sharedSecret, numBytes);
		} catch (InvalidKeyException e) {
			throw new IllegalArgumentException("Invalid keys", e);
		} finally {
			Arrays.fill(sharedSecret, (byte) 0x00);
		}
	}

	private static KeyAgreement createKeyAgreement() {
		try {
			return KeyAgreement.getInstance("ECDH");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("ECDH not supported");
		}
	}


}
