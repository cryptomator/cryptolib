package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.UnprotectedHeader;
import com.nimbusds.jose.crypto.impl.AESKW;
import com.nimbusds.jose.crypto.impl.ConcatKDF;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.ECDH;
import com.nimbusds.jose.crypto.impl.PBKDF2;
import com.nimbusds.jose.crypto.impl.PRFParams;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Reads and writes {@code vault.uvf}: a JWE in general JSON serialization with one recipient per party that can unlock the vault.
 * <p>
 * nimbus' high-level encrypters/decrypters can not share one content encryption key across PBES2 and ECDH-ES recipients and never expose the CEK, so this codec uses nimbus' JWE object
 * model for the structure and its {@code crypto.impl} primitives for key wrapping and content encryption.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/tree/develop/vault%20metadata">UVF vault metadata</a>
 */
final class UvfMetadataCodec {

	static final JWEAlgorithm PASSWORD_ALG = JWEAlgorithm.PBES2_HS512_A256KW;
	static final JWEAlgorithm ECDH_ALG = JWEAlgorithm.ECDH_ES_A256KW;
	static final JWEAlgorithm KEY_WRAP_ALG = JWEAlgorithm.A256KW;
	static final int PBES2_SALT_LEN = 16;
	static final int PBES2_MIN_ITERATIONS = 1000;
	static final int PBES2_MAX_ITERATIONS = 1_000_000;
	static final int MAX_PAYLOAD_SIZE = 1_000_000;
	private static final Set<JWEAlgorithm> PBES2_ALGS = new java.util.HashSet<>(Arrays.asList(JWEAlgorithm.PBES2_HS256_A128KW, JWEAlgorithm.PBES2_HS384_A192KW, JWEAlgorithm.PBES2_HS512_A256KW));
	private static final Set<JWEAlgorithm> ECDH_ALGS = new java.util.HashSet<>(Arrays.asList(JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.ECDH_ES_A192KW, JWEAlgorithm.ECDH_ES_A256KW));
	private static final Set<JWEAlgorithm> KW_ALGS = new java.util.HashSet<>(Arrays.asList(JWEAlgorithm.A128KW, JWEAlgorithm.A192KW, JWEAlgorithm.A256KW));
	private static final JWEJCAContext JCA = new JWEJCAContext();

	private UvfMetadataCodec() {
	}

	/**
	 * Parses a {@code vault.uvf} file and validates its protected header.
	 *
	 * @param json The file contents
	 * @return The parsed JWE
	 * @throws VaultConfigLoadException If the file is malformed or violates UVF's structural rules
	 * @throws UnsupportedVaultFormatException If it is for another UVF specification version
	 */
	static JWEObjectJSON parse(String json) throws VaultConfigLoadException, UnsupportedVaultFormatException {
		JWEObjectJSON jwe;
		try {
			jwe = JWEObjectJSON.parse(json);
		} catch (ParseException e) {
			throw new VaultConfigLoadException("Malformed vault.uvf", e);
		}
		JWEHeader header = jwe.getHeader();
		Set<String> crit = header.getCriticalParams();
		if (crit == null || !crit.equals(Collections.singleton(Constants.SPEC_VERSION_HEADER))) {
			throw new VaultConfigLoadException("Unsupported critical header parameters: " + crit);
		}
		int specVersion = specVersion(header);
		if (specVersion != Constants.SPEC_VERSION) {
			throw new UnsupportedVaultFormatException(specVersion, Constants.SPEC_VERSION);
		}
		if (!EncryptionMethod.A256GCM.equals(header.getEncryptionMethod())) {
			throw new VaultConfigLoadException("Unsupported encryption method: " + header.getEncryptionMethod());
		}
		if (header.getCompressionAlgorithm() != null) {
			throw new VaultConfigLoadException("Compression is not allowed");
		}
		if (header.getAlgorithm() != null || header.getKeyID() != null) {
			throw new VaultConfigLoadException("alg and kid must be per-recipient header parameters");
		}
		if (jwe.getRecipients().isEmpty()) {
			throw new VaultConfigLoadException("No recipients");
		}
		return jwe;
	}

	/**
	 * @param header A protected header
	 * @return The value of {@code uvf.spec.version}, or {@code -1} if absent or malformed
	 */
	static int specVersion(JWEHeader header) {
		Object value = header.getCustomParam(Constants.SPEC_VERSION_HEADER);
		return value instanceof Number ? ((Number) value).intValue() : -1;
	}

	/**
	 * @return The protected header for a new vault
	 */
	static JWEHeader newProtectedHeader() {
		return new JWEHeader.Builder(EncryptionMethod.A256GCM) //
				.contentType(Constants.CONTENT_TYPE) //
				.criticalParams(Collections.singleton(Constants.SPEC_VERSION_HEADER)) //
				.customParam(Constants.SPEC_VERSION_HEADER, Constants.SPEC_VERSION) //
				.build();
	}

	/**
	 * @param csprng Source of randomness
	 * @return A fresh 256 bit content encryption key
	 */
	static SecretKey newContentKey(SecureRandom csprng) {
		try {
			return ContentCryptoProvider.generateCEK(EncryptionMethod.A256GCM, csprng);
		} catch (JOSEException e) {
			throw new IllegalStateException(e);
		}
	}

	static String alg(JWEObjectJSON.Recipient recipient) {
		Object alg = recipient.getUnprotectedHeader() == null ? null : recipient.getUnprotectedHeader().getParam("alg");
		return alg == null ? null : alg.toString();
	}

	private static JWEHeader joinedHeader(JWEObjectJSON jwe, JWEObjectJSON.Recipient recipient) throws VaultConfigLoadException {
		if (recipient.getUnprotectedHeader() == null) {
			throw new VaultConfigLoadException("Recipient lacks a per-recipient header");
		}
		try {
			return (JWEHeader) jwe.getHeader().join(recipient.getUnprotectedHeader());
		} catch (ParseException e) {
			throw new VaultConfigLoadException("Malformed recipient header", e);
		}
	}

	// UNWRAP

	/**
	 * Unwraps the content encryption key as a password-based recipient.
	 *
	 * @param jwe The parsed JWE
	 * @param recipient The recipient to unlock as
	 * @param password The password
	 * @return The content encryption key
	 * @throws VaultKeyInvalidException If the password is wrong
	 * @throws VaultConfigLoadException If the recipient does not use a PBES2 algorithm or its parameters are invalid
	 */
	static SecretKey unwrapWithPassword(JWEObjectJSON jwe, JWEObjectJSON.Recipient recipient, CharSequence password) throws VaultKeyInvalidException, VaultConfigLoadException {
		JWEHeader header = joinedHeader(jwe, recipient);
		JWEAlgorithm alg = header.getAlgorithm();
		if (!PBES2_ALGS.contains(alg)) {
			throw new VaultConfigLoadException("Recipient is not password-based: " + alg);
		}
		if (header.getPBES2Salt() == null || header.getPBES2Count() < PBES2_MIN_ITERATIONS || header.getPBES2Count() > PBES2_MAX_ITERATIONS) {
			throw new VaultConfigLoadException("Invalid PBES2 parameters");
		}
		byte[] passwordBytes = utf8(password);
		try {
			byte[] salt = PBKDF2.formatSalt(alg, header.getPBES2Salt().decode());
			SecretKey kek = PBKDF2.deriveKey(passwordBytes, salt, header.getPBES2Count(), PRFParams.resolve(alg, null), null);
			return AESKW.unwrapCEK(kek, recipient.getEncryptedKey().decode(), null);
		} catch (JOSEException e) {
			throw new VaultKeyInvalidException("Wrong password", e);
		} finally {
			Arrays.fill(passwordBytes, (byte) 0x00);
		}
	}

	/**
	 * Unwraps the content encryption key as an ECDH-ES recipient.
	 *
	 * @param jwe The parsed JWE
	 * @param recipient The recipient to unlock as
	 * @param privateKey The recipient's EC private key
	 * @return The content encryption key
	 * @throws VaultKeyInvalidException If the key does not match
	 * @throws VaultConfigLoadException If the recipient does not use an ECDH-ES key wrapping algorithm or lacks an ephemeral key
	 */
	static SecretKey unwrapWithPrivateKey(JWEObjectJSON jwe, JWEObjectJSON.Recipient recipient, ECPrivateKey privateKey) throws VaultKeyInvalidException, VaultConfigLoadException {
		JWEHeader header = joinedHeader(jwe, recipient);
		JWEAlgorithm alg = header.getAlgorithm();
		if (!ECDH_ALGS.contains(alg)) {
			throw new VaultConfigLoadException("Recipient is not ECDH-ES key wrapping based: " + alg);
		}
		if (header.getEphemeralPublicKey() == null || !(header.getEphemeralPublicKey() instanceof ECKey)) {
			throw new VaultConfigLoadException("Recipient lacks an EC ephemeral public key");
		}
		try {
			ECPublicKey epk = ((ECKey) header.getEphemeralPublicKey()).toECPublicKey();
			SecretKey z = ECDH.deriveSharedSecret(epk, privateKey, null);
			SecretKey kek = ECDH.deriveSharedKey(header, z, new ConcatKDF("SHA-256"));
			return AESKW.unwrapCEK(kek, recipient.getEncryptedKey().decode(), null);
		} catch (JOSEException e) {
			throw new VaultKeyInvalidException("Wrong private key", e);
		}
	}

	/**
	 * Unwraps the content encryption key with an AES key encryption key.
	 *
	 * @param jwe The parsed JWE
	 * @param recipient The recipient to unlock as
	 * @param keyEncryptionKey The key encryption key
	 * @return The content encryption key
	 * @throws VaultKeyInvalidException If the key does not match
	 * @throws VaultConfigLoadException If the recipient does not use an AES key wrapping algorithm
	 */
	static SecretKey unwrapWithKeyEncryptionKey(JWEObjectJSON jwe, JWEObjectJSON.Recipient recipient, SecretKey keyEncryptionKey) throws VaultKeyInvalidException, VaultConfigLoadException {
		JWEHeader header = joinedHeader(jwe, recipient);
		if (!KW_ALGS.contains(header.getAlgorithm())) {
			throw new VaultConfigLoadException("Recipient is not AES key wrapping based: " + header.getAlgorithm());
		}
		try {
			return AESKW.unwrapCEK(keyEncryptionKey, recipient.getEncryptedKey().decode(), null);
		} catch (JOSEException e) {
			throw new VaultKeyInvalidException("Wrong key encryption key", e);
		}
	}

	// CONTENT

	/**
	 * @param jwe The parsed JWE
	 * @param contentKey The content encryption key
	 * @return The decrypted payload
	 * @throws VaultKeyInvalidException If the content does not authenticate with this key
	 */
	static byte[] decryptPayload(JWEObjectJSON jwe, SecretKey contentKey) throws VaultKeyInvalidException {
		try {
			// the last argument caps the size of decompressed payloads; compression is rejected by parse(), so it never applies
			return ContentCryptoProvider.decrypt(jwe.getHeader(), jwe.getAAD(), null, jwe.getIV(), jwe.getCipherText(), jwe.getAuthTag(), contentKey, JCA, MAX_PAYLOAD_SIZE);
		} catch (JOSEException e) {
			throw new VaultKeyInvalidException("Failed to decrypt vault metadata", e);
		}
	}

	/**
	 * @param protectedHeader The protected header
	 * @param payload The payload to encrypt
	 * @param contentKey The content encryption key
	 * @param recipients The recipients, each wrapping {@code contentKey}
	 * @return The general JSON serialization
	 */
	static String serialize(JWEHeader protectedHeader, byte[] payload, SecretKey contentKey, List<JWEObjectJSON.Recipient> recipients) {
		byte[] aad = protectedHeader.toBase64URL().toString().getBytes(StandardCharsets.US_ASCII);
		try {
			JWECryptoParts parts = ContentCryptoProvider.encrypt(protectedHeader, payload, aad, contentKey, null, JCA);
			JWEObjectJSON jwe = new JWEObjectJSON(protectedHeader, parts.getCipherText(), parts.getInitializationVector(), parts.getAuthenticationTag(), recipients, null, null);
			return jwe.serializeGeneral();
		} catch (JOSEException e) {
			throw new IllegalStateException("Failed to encrypt vault metadata", e);
		}
	}

	// WRAP

	/**
	 * @param kid Key id of the new recipient
	 * @param password The password
	 * @param iterationCount PBKDF2 iterations
	 * @param contentKey The content encryption key to wrap
	 * @param csprng Source of the salt
	 * @return A {@code PBES2-HS512+A256KW} recipient
	 */
	static JWEObjectJSON.Recipient wrapWithPassword(String kid, CharSequence password, int iterationCount, SecretKey contentKey, SecureRandom csprng) {
		if (iterationCount < PBES2_MIN_ITERATIONS || iterationCount > PBES2_MAX_ITERATIONS) {
			throw new IllegalArgumentException("Iteration count must be within [" + PBES2_MIN_ITERATIONS + ", " + PBES2_MAX_ITERATIONS + "]");
		}
		byte[] salt = new byte[PBES2_SALT_LEN];
		csprng.nextBytes(salt);
		byte[] passwordBytes = utf8(password);
		try {
			SecretKey kek = PBKDF2.deriveKey(passwordBytes, PBKDF2.formatSalt(PASSWORD_ALG, salt), iterationCount, PRFParams.resolve(PASSWORD_ALG, null), null);
			byte[] encryptedKey = AESKW.wrapCEK(contentKey, kek, null);
			UnprotectedHeader header = new UnprotectedHeader.Builder() //
					.param("alg", PASSWORD_ALG.getName()) //
					.keyID(kid) //
					.param("p2s", Base64URL.encode(salt).toString()) //
					.param("p2c", iterationCount) //
					.build();
			return new JWEObjectJSON.Recipient(header, Base64URL.encode(encryptedKey));
		} catch (JOSEException e) {
			throw new IllegalStateException("Failed to wrap content key", e);
		} finally {
			Arrays.fill(passwordBytes, (byte) 0x00);
		}
	}

	/**
	 * @param kid Key id of the new recipient
	 * @param publicKey The recipient's EC public key
	 * @param contentKey The content encryption key to wrap
	 * @param csprng Source of the ephemeral key
	 * @return An {@code ECDH-ES+A256KW} recipient
	 */
	static JWEObjectJSON.Recipient wrapWithPublicKey(String kid, ECPublicKey publicKey, SecretKey contentKey, SecureRandom csprng) {
		try {
			Curve curve = Curve.forECParameterSpec(publicKey.getParams());
			if (curve == null) {
				throw new IllegalArgumentException("Unsupported EC curve");
			}
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(publicKey.getParams(), csprng);
			KeyPair ephemeral = generator.generateKeyPair();
			ECKey epk = new ECKey.Builder(curve, (ECPublicKey) ephemeral.getPublic()).build();
			JWEHeader kdfHeader = new JWEHeader.Builder(ECDH_ALG, EncryptionMethod.A256GCM).ephemeralPublicKey(epk).build();
			SecretKey z = ECDH.deriveSharedSecret(publicKey, ephemeral.getPrivate(), null);
			SecretKey kek = ECDH.deriveSharedKey(kdfHeader, z, new ConcatKDF("SHA-256"));
			byte[] encryptedKey = AESKW.wrapCEK(contentKey, kek, null);
			UnprotectedHeader header = new UnprotectedHeader.Builder() //
					.param("alg", ECDH_ALG.getName()) //
					.keyID(kid) //
					.param("epk", epk.toJSONObject()) //
					.build();
			return new JWEObjectJSON.Recipient(header, Base64URL.encode(encryptedKey));
		} catch (NoSuchAlgorithmException | java.security.InvalidAlgorithmParameterException | JOSEException e) {
			throw new IllegalStateException("Failed to wrap content key", e);
		}
	}

	/**
	 * @param kid Key id of the new recipient
	 * @param keyEncryptionKey A 256 bit AES key
	 * @param contentKey The content encryption key to wrap
	 * @return An {@code A256KW} recipient
	 */
	static JWEObjectJSON.Recipient wrapWithKeyEncryptionKey(String kid, SecretKey keyEncryptionKey, SecretKey contentKey) {
		if (keyEncryptionKey.getEncoded() == null || keyEncryptionKey.getEncoded().length != 32) {
			throw new IllegalArgumentException("Key encryption key must be a 256 bit AES key");
		}
		try {
			byte[] encryptedKey = AESKW.wrapCEK(contentKey, new SecretKeySpec(keyEncryptionKey.getEncoded(), "AES"), null);
			UnprotectedHeader header = new UnprotectedHeader.Builder().param("alg", KEY_WRAP_ALG.getName()).keyID(kid).build();
			return new JWEObjectJSON.Recipient(header, Base64URL.encode(encryptedKey));
		} catch (JOSEException e) {
			throw new IllegalStateException("Failed to wrap content key", e);
		}
	}

	private static byte[] utf8(CharSequence chars) {
		ByteBuffer buf = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
		byte[] result = new byte[buf.remaining()];
		buf.get(result);
		Arrays.fill(buf.array(), (byte) 0x00);
		return result;
	}

}
