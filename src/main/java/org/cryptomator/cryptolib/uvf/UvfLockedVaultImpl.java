package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;
import org.jspecify.annotations.Nullable;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

/**
 * {@link UvfLockedVault} backed by a parsed {@code vault.uvf} JWE.
 */
public final class UvfLockedVaultImpl implements UvfLockedVault {

	private final byte[] encoded;
	private final String json;
	private final JWEObjectJSON jwe;

	private UvfLockedVaultImpl(byte[] encoded, String json, JWEObjectJSON jwe) {
		this.encoded = encoded;
		this.json = json;
		this.jwe = jwe;
	}

	/**
	 * @param encoded The file contents
	 * @param json The file contents as trimmed string
	 * @return The locked vault
	 * @throws VaultConfigLoadException If the file is malformed
	 * @throws UnsupportedVaultFormatException If the file is for another UVF specification version
	 */
	public static UvfLockedVaultImpl parse(byte[] encoded, String json) throws VaultConfigLoadException, UnsupportedVaultFormatException {
		return new UvfLockedVaultImpl(encoded.clone(), json, UvfMetadataCodec.parse(json));
	}

	@Override
	public String configFileName() {
		return Constants.CONFIG_FILE_NAME;
	}

	@Override
	public byte[] encoded() {
		return encoded.clone();
	}

	@Override
	public int allegedSpecVersion() {
		return UvfMetadataCodec.specVersion(jwe.getHeader());
	}

	@Override
	public @Nullable String keyEncryptionKid() {
		if (UvfMetadataCodec.recipientHeader(jwe, PASSWORD_KID) != null) {
			return PASSWORD_KID;
		} else if (UvfMetadataCodec.recipientHeader(jwe, MEMBER_KEY_KID) != null) {
			return MEMBER_KEY_KID;
		} else {
			return null;
		}
	}

	@Override
	public @Nullable String recoveryKid() {
		return UvfMetadataCodec.findKid(jwe, RECOVERY_KEY_KID_PREFIX);
	}

	@Override
	public UvfUnlockedVault unlock(CharSequence password, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException {
		Map<String, Object> header = requireRecipient(PASSWORD_KID);
		byte[] kek = Argon2Kdf.deriveKey(password, header);
		try {
			OctetSequenceKey key = new OctetSequenceKey.Builder(kek).keyID(PASSWORD_KID).algorithm(JWEAlgorithm.A256KW).build();
			return unlock(key, Argon2Kdf.headerParams(header), csprng);
		} finally {
			Arrays.fill(kek, (byte) 0x00);
		}
	}

	@Override
	public UvfUnlockedVault unlock(SecretKey memberKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException {
		requireRecipient(MEMBER_KEY_KID);
		OctetSequenceKey key = new OctetSequenceKey.Builder(memberKey).keyID(MEMBER_KEY_KID).algorithm(JWEAlgorithm.A256KW).build();
		return unlock(key, Collections.<String, Object>emptyMap(), csprng);
	}

	@Override
	public UvfUnlockedVault recover(ECPrivateKey recoveryKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException {
		String kid = recoveryKid();
		if (kid == null) {
			throw new VaultConfigLoadException("Vault has no recovery key entry");
		}
		ECKey publicKey = recoveryPublicKey(kid);
		ECKey key = new ECKey.Builder(publicKey).privateKey(recoveryKey).keyID(kid).build();
		return new UvfVault(seeds(key), jwe.getHeader(), null, Collections.<String, Object>emptyMap(), publicKey, csprng);
	}

	private UvfUnlockedVault unlock(OctetSequenceKey key, Map<String, Object> keyParams, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException {
		String kid = recoveryKid();
		@Nullable ECKey recoveryKey = kid == null ? null : recoveryPublicKey(kid);
		return new UvfVault(seeds(key), jwe.getHeader(), key, keyParams, recoveryKey, csprng);
	}

	private UvfSeeds seeds(JWK key) throws VaultKeyInvalidException, VaultConfigLoadException {
		byte[] payload = UvfMetadataCodec.decrypt(UvfMetadataCodec.parse(json), key); // a JWE object can be decrypted only once
		try {
			return UvfSeeds.fromDecryptedPayload(new String(payload, StandardCharsets.UTF_8));
		} finally {
			Arrays.fill(payload, (byte) 0x00);
		}
	}

	private Map<String, Object> requireRecipient(String kid) throws VaultConfigLoadException {
		Map<String, Object> header = UvfMetadataCodec.recipientHeader(jwe, kid);
		if (header == null) {
			throw new VaultConfigLoadException("Vault has no recipient " + kid + " (key encryption key is " + keyEncryptionKid() + ")");
		}
		return header;
	}

	// the recovery key's public key is embedded in its entry; without it the vault could not be re-encrypted
	private ECKey recoveryPublicKey(String kid) throws VaultConfigLoadException {
		Map<String, Object> header = requireRecipient(kid);
		Object jwk =   header.get(UvfMetadataCodec.JWK_PARAM);
		if (!(jwk instanceof Map)) {
			throw new VaultConfigLoadException("Recovery key entry lacks its public key (" + UvfMetadataCodec.JWK_PARAM + ")");
		}
		try {
			@SuppressWarnings("unchecked")
			ECKey key = ECKey.parse((Map<String, Object>) jwk);
			if (key.isPrivate()) {
				throw new VaultConfigLoadException("Recovery key entry must not contain private key material");
			}
			return key;
		} catch (ParseException e) {
			throw new VaultConfigLoadException("Malformed recovery key", e);
		}
	}

}
