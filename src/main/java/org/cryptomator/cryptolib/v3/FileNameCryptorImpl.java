package org.cryptomator.cryptolib.v3;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.RevolvingMasterkey;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.MacSupplier;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;
import org.cryptomator.cryptolib.common.ObjectPool;
import org.cryptomator.siv.SivMode;
import org.cryptomator.siv.UnauthenticCiphertextException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;

class FileNameCryptorImpl implements FileNameCryptor {

	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final ObjectPool<SivMode> AES_SIV = new ObjectPool<>(SivMode::new);

	private final DestroyableSecretKey sivKey;
	private final DestroyableSecretKey hmacKey;

	/**
	 * Create a file name encryption/decryption tool for a certain masterkey revision.
	 * @param masterkey The masterkey from which to derive subkeys
	 * @param revision Which masterkey revision to use
	 * @throws IllegalArgumentException If no subkey could be derived for the given revision
	 */
	FileNameCryptorImpl(RevolvingMasterkey masterkey, int revision) throws IllegalArgumentException {
		this.sivKey = masterkey.subKey(revision, 64, "siv".getBytes(StandardCharsets.US_ASCII), "AES");
		this.hmacKey = masterkey.subKey(revision, 32, "hmac".getBytes(StandardCharsets.US_ASCII), "HMAC");
	}

	@Override
	public String hashDirectoryId(byte[] cleartextDirectoryId) {
		try (DestroyableSecretKey key = this.hmacKey.copy();
			 ObjectPool.Lease<Mac> hmacSha256 = MacSupplier.HMAC_SHA256.keyed(key)) {
			byte[] hash = hmacSha256.get().doFinal(cleartextDirectoryId);
			return BASE32.encode(hash, 0, 20); // only use first 160 bits
		}
	}

	@Override
	public String encryptFilename(BaseEncoding encoding, String cleartextName, byte[]... associatedData) {
		try (DestroyableSecretKey key = this.sivKey.copy(); ObjectPool.Lease<SivMode> siv = AES_SIV.get()) {
			byte[] cleartextBytes = cleartextName.getBytes(UTF_8);
			byte[] encryptedBytes = siv.get().encrypt(key, cleartextBytes, associatedData);
			return encoding.encode(encryptedBytes);
		}
	}

	@Override
	public String decryptFilename(BaseEncoding encoding, String ciphertextName, byte[]... associatedData) throws AuthenticationFailedException {
		try (DestroyableSecretKey key = this.sivKey.copy(); ObjectPool.Lease<SivMode> siv = AES_SIV.get()) {
			byte[] encryptedBytes = encoding.decode(ciphertextName);
			byte[] cleartextBytes = siv.get().decrypt(key, encryptedBytes, associatedData);
			return new String(cleartextBytes, UTF_8);
		} catch (IllegalArgumentException | UnauthenticCiphertextException | IllegalBlockSizeException e) {
			throw new AuthenticationFailedException("Invalid Ciphertext.", e);
		}
	}

}
