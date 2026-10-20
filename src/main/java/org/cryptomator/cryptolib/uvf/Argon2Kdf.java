package org.cryptomator.cryptolib.uvf;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.cryptomator.cryptolib.api.Argon2Params;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Derives the key encryption key of the password recipient: Argon2id (version 1.3, 256 bit output) with the salt and cost parameters stored in the recipient's header as
 * {@code org.cryptomator.password.argon2.salt} (base64url, 16 bytes), {@code .memoryKiB}, {@code .iterations} and {@code .parallelism}.
 */
final class Argon2Kdf {

	static final String SALT_PARAM = UvfLockedVault.PASSWORD_KID + ".salt";
	static final String MEMORY_PARAM = UvfLockedVault.PASSWORD_KID + ".memoryKiB";
	static final String ITERATIONS_PARAM = UvfLockedVault.PASSWORD_KID + ".iterations";
	static final String PARALLELISM_PARAM = UvfLockedVault.PASSWORD_KID + ".parallelism";
	static final List<String> PARAMS = Collections.unmodifiableList(Arrays.asList(SALT_PARAM, MEMORY_PARAM, ITERATIONS_PARAM, PARALLELISM_PARAM));
	static final int SALT_LEN = 16;
	static final int KEY_LEN = 32;
	private static final int MIN_SALT_LEN = 8;

	private Argon2Kdf() {
	}

	/**
	 * @param params Cost parameters
	 * @param csprng Source of the salt
	 * @return The header parameters of a new password entry
	 */
	static Map<String, Object> newHeaderParams(Argon2Params params, SecureRandom csprng) {
		byte[] salt = new byte[SALT_LEN];
		csprng.nextBytes(salt);
		Map<String, Object> result = new LinkedHashMap<>();
		result.put(SALT_PARAM, Base64.getUrlEncoder().withoutPadding().encodeToString(salt));
		result.put(MEMORY_PARAM, params.memoryKiB());
		result.put(ITERATIONS_PARAM, params.iterations());
		result.put(PARALLELISM_PARAM, params.parallelism());
		return result;
	}

	/**
	 * @param password The password
	 * @param headerParams The header of the password entry, see {@link #newHeaderParams(Argon2Params, SecureRandom)}
	 * @return The 256 bit key encryption key; the caller must zero it after use
	 * @throws VaultConfigLoadException If the header lacks the Argon2 parameters or they are invalid
	 */
	static byte[] deriveKey(CharSequence password, Map<String, Object> headerParams) throws VaultConfigLoadException {
		byte[] salt = salt(headerParams);
		Argon2Params params;
		try {
			params = new Argon2Params(intParam(headerParams, MEMORY_PARAM), intParam(headerParams, ITERATIONS_PARAM), intParam(headerParams, PARALLELISM_PARAM));
		} catch (IllegalArgumentException e) {
			throw new VaultConfigLoadException("Invalid Argon2 parameters", e);
		}
		Argon2Parameters argon2 = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id) //
				.withVersion(Argon2Parameters.ARGON2_VERSION_13) //
				.withSalt(salt) //
				.withMemoryAsKB(params.memoryKiB()) //
				.withIterations(params.iterations()) //
				.withParallelism(params.parallelism()) //
				.build();
		ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
		byte[] passwordBytes = new byte[encoded.remaining()];
		encoded.get(passwordBytes);
		Arrays.fill(encoded.array(), (byte) 0x00);
		try {
			Argon2BytesGenerator generator = new Argon2BytesGenerator();
			generator.init(argon2);
			byte[] key = new byte[KEY_LEN];
			generator.generateBytes(passwordBytes, key);
			return key;
		} finally {
			Arrays.fill(passwordBytes, (byte) 0x00);
		}
	}

	/**
	 * @param header The header of a password entry
	 * @return Its Argon2 parameters only, to carry over when the vault is re-encrypted
	 */
	static Map<String, Object> headerParams(Map<String, Object> header) {
		Map<String, Object> result = new LinkedHashMap<>();
		for (String param : PARAMS) {
			result.put(param, header.get(param));
		}
		return result;
	}

	private static byte[] salt(Map<String, Object> header) throws VaultConfigLoadException {
		Object value = header.get(SALT_PARAM);
		if (!(value instanceof String)) {
			throw new VaultConfigLoadException("Missing " + SALT_PARAM);
		}
		byte[] salt;
		try {
			salt = Base64.getUrlDecoder().decode((String) value);
		} catch (IllegalArgumentException e) {
			throw new VaultConfigLoadException("Malformed " + SALT_PARAM, e);
		}
		if (salt.length < MIN_SALT_LEN) {
			throw new VaultConfigLoadException("Argon2 salt too short");
		}
		return salt;
	}

	private static int intParam(Map<String, Object> header, String name) throws VaultConfigLoadException {
		Object value = header.get(name);
		if (!(value instanceof Number) || ((Number) value).longValue() != ((Number) value).intValue()) {
			throw new VaultConfigLoadException("Missing or invalid " + name);
		}
		return ((Number) value).intValue();
	}

}
