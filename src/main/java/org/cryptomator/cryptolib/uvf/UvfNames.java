package org.cryptomator.cryptolib.uvf;

import org.bouncycastle.util.encoders.Base32;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.MacSupplier;
import org.cryptomator.cryptolib.internal.CleartextNames;
import org.cryptomator.siv.SivMode;
import org.cryptomator.siv.UnauthenticCiphertextException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * File name encryption (AES-SIV-512, unpadded base64url) and directory id hashing of UVF, with per-seed subkeys.
 */
final class UvfNames {

	private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();
	private static final SivMode AES_SIV = new SivMode(); // thread-safe, uses thread-local block ciphers
	private static final int DIR_HASH_LEN = 20; // only the leftmost 160 bits of the HMAC are used

	private final UvfSeeds seeds;
	private final Map<Integer, SeedKeys> keysBySeed = new ConcurrentHashMap<>();

	UvfNames(UvfSeeds seeds) {
		this.seeds = seeds;
	}

	private static final class SeedKeys {

		final DestroyableSecretKey sivKey;
		final DestroyableSecretKey hmacKey;

		SeedKeys(DestroyableSecretKey sivKey, DestroyableSecretKey hmacKey) {
			this.sivKey = sivKey;
			this.hmacKey = hmacKey;
		}

	}

	private SeedKeys keys(int seedId) {
		return keysBySeed.computeIfAbsent(seedId, id -> new SeedKeys( //
				seeds.subKey(id, 64, Constants.KDF_CONTEXT_SIV, "AES"), //
				seeds.subKey(id, 64, Constants.KDF_CONTEXT_HMAC, "HMAC")));
	}

	/**
	 * @param dirId A directory id
	 * @param seedId The directory's seed
	 * @return A 32 character base32 string: the leftmost 160 bits of HMAC-SHA256(dirId)
	 */
	String hashDirectoryId(byte[] dirId, int seedId) {
		try (DestroyableSecretKey key = keys(seedId).hmacKey.copy()) {
			Mac hmacSha256 = MacSupplier.HMAC_SHA256.keyed(key);
			byte[] hash = hmacSha256.doFinal(dirId);
			return Base32.toBase32String(Arrays.copyOf(hash, DIR_HASH_LEN));
		}
	}

	/**
	 * @param cleartextName A cleartext file name (normalized to NFC before encryption)
	 * @param dirId The id of the directory containing the file (associated data)
	 * @param seedId The directory's seed
	 * @return The unpadded base64url-encoded AES-SIV ciphertext, without any extension
	 */
	String encryptName(String cleartextName, byte[] dirId, int seedId) {
		try (DestroyableSecretKey key = keys(seedId).sivKey.copy()) {
			byte[] cleartext = Normalizer.normalize(cleartextName, Normalizer.Form.NFC).getBytes(UTF_8);
			byte[] encrypted = AES_SIV.encrypt(key, cleartext, dirId);
			return BASE64URL.encodeToString(encrypted);
		}
	}

	/**
	 * @param ciphertextName The unpadded base64url-encoded AES-SIV ciphertext, without any extension
	 * @param dirId The id of the directory containing the file (associated data)
	 * @param seedId The directory's seed
	 * @return The cleartext file name
	 * @throws AuthenticationFailedException If the ciphertext is unauthentic, malformed or not canonically encoded, or the decrypted name is not a valid file name
	 */
	String decryptName(String ciphertextName, byte[] dirId, int seedId) throws AuthenticationFailedException {
		try (DestroyableSecretKey key = keys(seedId).sivKey.copy()) {
			byte[] encrypted = BASE64URL_DECODER.decode(ciphertextName);
			if (!BASE64URL.encodeToString(encrypted).equals(ciphertextName)) {
				throw new IllegalArgumentException("Non-canonical base64url"); // e.g. non-zero trailing bits: the file system's name uniqueness must apply to the ciphertext
			}
			byte[] cleartext = AES_SIV.decrypt(key, encrypted, dirId);
			return CleartextNames.validate(new String(cleartext, UTF_8));
		} catch (UnauthenticCiphertextException | IllegalArgumentException | IllegalBlockSizeException e) {
			throw new AuthenticationFailedException("Invalid Ciphertext.", e);
		}
	}

	void destroy() {
		for (SeedKeys keys : keysBySeed.values()) {
			keys.sivKey.destroy();
			keys.hmacKey.destroy();
		}
		keysBySeed.clear();
	}

}
