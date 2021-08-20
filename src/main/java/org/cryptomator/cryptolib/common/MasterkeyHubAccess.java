package org.cryptomator.cryptolib.common;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.cryptomator.cryptolib.ecies.EncryptedMessage;
import org.cryptomator.cryptolib.ecies.ECIntegratedEncryptionScheme;

import javax.crypto.AEADBadTagException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class MasterkeyHubAccess {

	private static final BaseEncoding BASE64_URL = BaseEncoding.base64Url().omitPadding();

	private MasterkeyHubAccess() {
	}

	/**
	 * Decrypts a masterkey retrieved from Cryptomator Hub
	 *
	 * @param devicePrivateKey  Private key of the device this ciphertext is intended for
	 * @param encodedCiphertext The encrypted masterkey
	 * @param encodedEphPubKey  The ephemeral public key to be used to derive a secret shared between message sender and this device
	 * @return The decrypted masterkey
	 * @throws MasterkeyLoadingFailedException If the parameters don't match and decryption fails
	 */
	public static Masterkey decryptMasterkey(ECPrivateKey devicePrivateKey, String encodedCiphertext, String encodedEphPubKey) throws MasterkeyLoadingFailedException {
		byte[] cleartext = new byte[0];
		try {
			EncryptedMessage message = decode(encodedCiphertext, encodedEphPubKey);
			cleartext = ECIntegratedEncryptionScheme.HUB.decrypt(devicePrivateKey, message);
			return new Masterkey(cleartext);
		} catch (IllegalArgumentException | AEADBadTagException e) {
			throw new MasterkeyLoadingFailedException("Key and ciphertext don't match", e);
		} finally {
			Arrays.fill(cleartext, (byte) 0x00);
		}
	}

	private static EncryptedMessage decode(String encodedCiphertext, String encodedEphPubKey) throws IllegalArgumentException {
		byte[] ciphertext = BASE64_URL.decode(encodedCiphertext);
		byte[] keyBytes = BASE64_URL.decode(encodedEphPubKey);
		try {
			PublicKey key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(keyBytes));
			if (key instanceof ECPublicKey) {
				return new EncryptedMessage((ECPublicKey) key, ciphertext);
			} else {
				throw new IllegalArgumentException("Key not an EC public key.");
			}
		} catch (InvalidKeySpecException e) {
			throw new IllegalArgumentException("Invalid license public key", e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

}
