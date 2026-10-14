package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.UnprotectedHeader;
import com.nimbusds.jose.crypto.MultiDecrypter;
import com.nimbusds.jose.crypto.MultiEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;
import org.jspecify.annotations.Nullable;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads and writes {@code vault.uvf}: a JWE in general JSON serialization with two recipients, encrypted and decrypted with nimbus' multi-recipient API.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/tree/develop/vault%20metadata">UVF vault metadata</a>
 */
final class UvfMetadataCodec {

	/** Header parameter carrying the recovery key's public JWK in its recipient entry, so that the vault can be re-encrypted for it. */
	static final String JWK_PARAM = "jwk";
	private static final Set<String> DEFERRED_CRITICAL_HEADERS = Collections.singleton(Constants.SPEC_VERSION_HEADER);

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
		if (crit == null || !crit.equals(DEFERRED_CRITICAL_HEADERS)) {
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
				.criticalParams(DEFERRED_CRITICAL_HEADERS) //
				.customParam(Constants.SPEC_VERSION_HEADER, Constants.SPEC_VERSION) //
				.build();
	}

	/**
	 * @param jwe The parsed JWE
	 * @param kid A recipient's key id
	 * @return The per-recipient header of the first entry with this kid, or {@code null} if there is none
	 */
	static @Nullable Map<String, Object> recipientHeader(JWEObjectJSON jwe, String kid) {
		for (JWEObjectJSON.Recipient recipient : jwe.getRecipients()) {
			UnprotectedHeader header = recipient.getUnprotectedHeader();
			if (header != null && kid.equals(header.getKeyID())) {
				return header.toJSONObject();
			}
		}
		return null;
	}

	/**
	 * @param jwe The parsed JWE
	 * @param prefix A key id prefix
	 * @return The key id of the first entry whose kid starts with the prefix, or {@code null} if there is none
	 */
	static @Nullable String findKid(JWEObjectJSON jwe, String prefix) {
		for (JWEObjectJSON.Recipient recipient : jwe.getRecipients()) {
			UnprotectedHeader header = recipient.getUnprotectedHeader();
			if (header != null && header.getKeyID() != null && header.getKeyID().startsWith(prefix)) {
				return header.getKeyID();
			}
		}
		return null;
	}

	/**
	 * Decrypts the metadata as the recipient whose kid matches the key's.
	 *
	 * @param jwe The parsed JWE, which must be in encrypted state (parse it freshly for each attempt)
	 * @param key The recipient's key with its {@code kid} set: a 256 bit {@link OctetSequenceKey} for {@code A256KW} entries or a private {@link ECKey} for {@code ECDH-ES+A256KW} entries
	 * @return The decrypted payload
	 * @throws VaultKeyInvalidException If the key does not match
	 */
	static byte[] decrypt(JWEObjectJSON jwe, JWK key) throws VaultKeyInvalidException {
		try {
			jwe.decrypt(new MultiDecrypter(key, DEFERRED_CRITICAL_HEADERS));
			return jwe.getPayload().toBytes();
		} catch (JOSEException e) {
			throw new VaultKeyInvalidException("Failed to unlock as recipient " + key.getKeyID(), e);
		}
	}

	/**
	 * Encrypts the metadata with a fresh content key for both recipients.
	 *
	 * @param protectedHeader The protected header
	 * @param payload The payload to encrypt
	 * @param keyEncryptionKey The {@code A256KW} recipient's key with its {@code kid} set
	 * @param keyEncryptionKeyParams Additional per-recipient header parameters for that entry, e.g. the Argon2 parameters
	 * @param recoveryKey The recovery key recipient's key with its {@code kid} set; only its public part is used, which is also embedded in the entry as {@value #JWK_PARAM}
	 * @return The general JSON serialization
	 */
	static String serialize(JWEHeader protectedHeader, byte[] payload, OctetSequenceKey keyEncryptionKey, Map<String, Object> keyEncryptionKeyParams, ECKey recoveryKey) {
		try {
			JWEObjectJSON jwe = new JWEObjectJSON(protectedHeader, new Payload(payload));
			jwe.encrypt(new MultiEncrypter(new JWKSet(Arrays.<JWK>asList(keyEncryptionKey, recoveryKey.toPublicJWK()))));
			// nimbus only carries kid, alg and x5* into the per-recipient headers; the rest is added afterwards (the recipient headers are unprotected)
			List<JWEObjectJSON.Recipient> recipients = new ArrayList<>();
			for (JWEObjectJSON.Recipient recipient : jwe.getRecipients()) {
				Map<String, Object> header = new LinkedHashMap<>(recipient.getUnprotectedHeader().toJSONObject());
				if (keyEncryptionKey.getKeyID().equals(recipient.getUnprotectedHeader().getKeyID())) {
					header.putAll(keyEncryptionKeyParams);
				} else {
					header.put(JWK_PARAM, recoveryKey.toPublicJWK().toJSONObject());
				}
				recipients.add(new JWEObjectJSON.Recipient(UnprotectedHeader.parse(header), recipient.getEncryptedKey()));
			}
			return new JWEObjectJSON(jwe.getHeader(), jwe.getCipherText(), jwe.getIV(), jwe.getAuthTag(), recipients, null, null).serializeGeneral();
		} catch (JOSEException | ParseException e) {
			throw new IllegalStateException("Failed to encrypt vault metadata", e);
		}
	}

}
