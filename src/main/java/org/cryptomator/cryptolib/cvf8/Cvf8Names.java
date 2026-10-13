package org.cryptomator.cryptolib.cvf8;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.MessageDigestSupplier;
import org.cryptomator.cryptolib.common.ObjectPool;
import org.cryptomator.siv.SivMode;
import org.cryptomator.siv.UnauthenticCiphertextException;

import javax.crypto.IllegalBlockSizeException;
import java.security.MessageDigest;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * File name encryption (AES-SIV, base64url), directory id hashing and name shortening of CVF8.
 */
final class Cvf8Names {

	private static final BaseEncoding BASE32 = BaseEncoding.base32();
	private static final BaseEncoding BASE64URL = BaseEncoding.base64Url();
	private static final ObjectPool<SivMode> AES_SIV = new ObjectPool<>(SivMode::new);

	private final CvfMasterkey masterkey;

	Cvf8Names(CvfMasterkey masterkey) {
		this.masterkey = masterkey;
	}

	/**
	 * @param dirId A directory id
	 * @return A 32 character base32 string: SHA-1 of the AES-SIV encrypted id
	 */
	String hashDirectoryId(String dirId) {
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey();
			 ObjectPool.Lease<MessageDigest> sha1 = MessageDigestSupplier.SHA1.instance();
			 ObjectPool.Lease<SivMode> siv = AES_SIV.get()) {
			byte[] encrypted = siv.get().encrypt(ek, mk, dirId.getBytes(UTF_8));
			byte[] hashed = sha1.get().digest(encrypted);
			return BASE32.encode(hashed);
		}
	}

	/**
	 * @param cleartextName A cleartext file name
	 * @param dirId The id of the directory containing the file
	 * @return The base64url-encoded AES-SIV ciphertext, without any extension
	 */
	String encryptName(String cleartextName, String dirId) {
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey(); ObjectPool.Lease<SivMode> siv = AES_SIV.get()) {
			byte[] encrypted = siv.get().encrypt(ek, mk, cleartextName.getBytes(UTF_8), dirId.getBytes(UTF_8));
			return BASE64URL.encode(encrypted);
		}
	}

	/**
	 * @param ciphertextName The base64url-encoded AES-SIV ciphertext, without any extension
	 * @param dirId The id of the directory containing the file
	 * @return The cleartext file name
	 * @throws AuthenticationFailedException If the ciphertext is unauthentic or malformed
	 */
	String decryptName(String ciphertextName, String dirId) throws AuthenticationFailedException {
		try (DestroyableSecretKey ek = masterkey.getEncKey(); DestroyableSecretKey mk = masterkey.getMacKey(); ObjectPool.Lease<SivMode> siv = AES_SIV.get()) {
			byte[] encrypted = BASE64URL.decode(ciphertextName);
			byte[] cleartext = siv.get().decrypt(ek, mk, encrypted, dirId.getBytes(UTF_8));
			return new String(cleartext, UTF_8);
		} catch (UnauthenticCiphertextException | IllegalArgumentException | IllegalBlockSizeException e) {
			throw new AuthenticationFailedException("Invalid Ciphertext.", e);
		}
	}

	/**
	 * @param ciphertextName A full ciphertext name including its {@code .c9r} extension
	 * @return The shortened name: base64url(SHA-1(name)) + {@code .c9s}
	 */
	static String shorten(String ciphertextName) {
		try (ObjectPool.Lease<MessageDigest> sha1 = MessageDigestSupplier.SHA1.instance()) {
			byte[] hash = sha1.get().digest(ciphertextName.getBytes(UTF_8));
			return BASE64URL.encode(hash) + Constants.SHORTENED_FILE_EXT;
		}
	}

}
