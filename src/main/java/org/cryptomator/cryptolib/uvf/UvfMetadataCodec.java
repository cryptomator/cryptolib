package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
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
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;
import org.jspecify.annotations.Nullable;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Reads and writes {@code vault.uvf}: a JWE in general JSON serialization with two recipients, encrypted and decrypted with nimbus' multi-recipient API.
 * <p>
 * The unprotected per-recipient headers only carry {@code kid}, {@code alg} and the password recipient's Argon2 parameters; algorithms and public keys are taken from the payload's
 * {@code recipientDetails} and verified against the headers on unlock.
 *
 * @see <a href="https://github.com/encryption-alliance/unified-vault-format/tree/develop/vault%20metadata">UVF vault metadata</a>
 */
final class UvfMetadataCodec {

	private static final Set<String> DEFERRED_CRITICAL_HEADERS = Collections.singleton(Constants.SPEC_VERSION_HEADER);
	private static final Set<String> KEY_ENCRYPTION_KIDS = new HashSet<>(Arrays.asList(UvfLockedVault.PASSWORD_KID, UvfLockedVault.MEMBER_KEY_KID));

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
	 * Validates the (unauthenticated) recipient headers against the decrypted {@code recipientDetails}, as required by the specification, and checks that the vault follows cryptolib's
	 * two-recipient model: one key encryption key ({@link UvfLockedVault#PASSWORD_KID} or {@link UvfLockedVault#MEMBER_KEY_KID}, {@code A256KW}) and one recovery key
	 * ({@link UvfLockedVault#RECOVERY_KEY_KID}, {@code ECDH-ES+A256KW}).
	 *
	 * @param jwe The parsed JWE
	 * @param recipientDetails The decrypted payload's recipient details
	 * @throws VaultConfigLoadException If headers and details disagree or the recipients are not the expected two
	 */
	static void validateRecipients(JWEObjectJSON jwe, Map<String, UvfSeeds.RecipientDetails> recipientDetails) throws VaultConfigLoadException {
		Set<String> kids = new HashSet<>();
		for (JWEObjectJSON.Recipient recipient : jwe.getRecipients()) {
			UnprotectedHeader header = recipient.getUnprotectedHeader();
			String kid = header == null ? null : header.getKeyID();
			if (kid == null || !kids.add(kid)) {
				throw new VaultConfigLoadException("Recipient without kid or duplicate kid: " + kid);
			}
			UvfSeeds.RecipientDetails details = recipientDetails.get(kid);
			if (details == null) {
				throw new VaultConfigLoadException("Recipient " + kid + " has no recipientDetails entry");
			}
			if (!details.alg.equals(header.getParam("alg"))) {
				throw new VaultConfigLoadException("Recipient " + kid + ": alg differs from recipientDetails");
			}
		}
		if (!kids.equals(recipientDetails.keySet())) {
			throw new VaultConfigLoadException("recipients and recipientDetails disagree: " + kids + " vs. " + recipientDetails.keySet());
		}
		for (Map.Entry<String, UvfSeeds.RecipientDetails> entry : recipientDetails.entrySet()) {
			String kid = entry.getKey();
			UvfSeeds.RecipientDetails details = entry.getValue();
			JWEAlgorithm alg = JWEAlgorithm.parse(details.alg);
			boolean publicKeyAlg = JWEAlgorithm.Family.ASYMMETRIC.contains(alg);
			if (publicKeyAlg != (details.jwk != null)) {
				throw new VaultConfigLoadException("Recipient " + kid + ": jwk must be present exactly for public key algorithms");
			}
			if (details.jwk != null && details.jwk.containsKey("alg") && !details.alg.equals(details.jwk.get("alg"))) {
				throw new VaultConfigLoadException("Recipient " + kid + ": jwk alg differs from recipientDetails alg");
			}
			if (KEY_ENCRYPTION_KIDS.contains(kid)) {
				if (!JWEAlgorithm.A256KW.equals(alg)) {
					throw new VaultConfigLoadException("Recipient " + kid + ": unsupported alg " + alg);
				}
			} else if (UvfLockedVault.RECOVERY_KEY_KID.equals(kid)) {
				if (!JWEAlgorithm.ECDH_ES_A256KW.equals(alg)) {
					throw new VaultConfigLoadException("Recipient " + kid + ": unsupported alg " + alg);
				}
			} else {
				throw new VaultConfigLoadException("Unsupported recipient " + kid);
			}
		}
		if (kids.size() != 2 || !kids.contains(UvfLockedVault.RECOVERY_KEY_KID)) {
			throw new VaultConfigLoadException("Expected one key encryption key and one recovery key recipient, got " + kids);
		}
		UvfSeeds.RecipientDetails password = recipientDetails.get(UvfLockedVault.PASSWORD_KID);
		if (password != null) {
			Map<String, Object> header = Objects.requireNonNull(recipientHeader(jwe, UvfLockedVault.PASSWORD_KID));
			for (String param : Argon2Kdf.PARAMS) {
				if (!String.valueOf(header.get(param)).equals(String.valueOf(password.vendorFields.get(param)))) {
					throw new VaultConfigLoadException("Argon2 parameters in the header differ from the committed ones");
				}
			}
		}
	}

	/**
	 * Encrypts the metadata with a fresh content key for both recipients.
	 *
	 * @param protectedHeader The protected header
	 * @param payload The payload to encrypt, whose {@code recipientDetails} define the recipients
	 * @param recipientDetails The payload's recipient details: algorithms, the password recipient's Argon2 parameters, the recovery key's public JWK
	 * @param keyEncryptionKey The {@code A256KW} recipient's key with its {@code kid} set
	 * @return The general JSON serialization
	 */
	static String serialize(JWEHeader protectedHeader, byte[] payload, Map<String, UvfSeeds.RecipientDetails> recipientDetails, OctetSequenceKey keyEncryptionKey) {
		try {
			UvfSeeds.RecipientDetails kekDetails = recipientDetails.get(keyEncryptionKey.getKeyID());
			UvfSeeds.RecipientDetails recoveryDetails = recipientDetails.get(UvfLockedVault.RECOVERY_KEY_KID);
			if (kekDetails == null || recoveryDetails == null || recoveryDetails.jwk == null) {
				throw new IllegalStateException("Incomplete recipient details");
			}
			OctetSequenceKey kek = new OctetSequenceKey.Builder(keyEncryptionKey).algorithm(JWEAlgorithm.parse(kekDetails.alg)).build();
			ECKey recoveryKey = new ECKey.Builder(ECKey.parse(recoveryDetails.jwk).toPublicJWK()).keyID(UvfLockedVault.RECOVERY_KEY_KID).algorithm(JWEAlgorithm.parse(recoveryDetails.alg)).build();
			JWEObjectJSON jwe = new JWEObjectJSON(protectedHeader, new Payload(payload));
			jwe.encrypt(new MultiEncrypter(new JWKSet(Arrays.<JWK>asList(kek, recoveryKey))));
			// nimbus only carries kid, alg and x5* into the per-recipient headers; the password recipient's KDF parameters are added afterwards (the recipient headers are unprotected)
			List<JWEObjectJSON.Recipient> recipients = new ArrayList<>();
			for (JWEObjectJSON.Recipient recipient : jwe.getRecipients()) {
				Map<String, Object> header = new LinkedHashMap<>(recipient.getUnprotectedHeader().toJSONObject());
				if (keyEncryptionKey.getKeyID().equals(recipient.getUnprotectedHeader().getKeyID())) {
					header.putAll(kekDetails.vendorFields);
				}
				recipients.add(new JWEObjectJSON.Recipient(UnprotectedHeader.parse(header), recipient.getEncryptedKey()));
			}
			return new JWEObjectJSON(jwe.getHeader(), jwe.getCipherText(), jwe.getIV(), jwe.getAuthTag(), recipients, null, null).serializeGeneral();
		} catch (JOSEException | ParseException e) {
			throw new IllegalStateException("Failed to encrypt vault metadata", e);
		}
	}

}
