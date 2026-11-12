package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObjectJSON;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;
import org.cryptomator.cryptolib.api.VaultRollbackException;
import org.cryptomator.cryptolib.internal.RecoveryKeys;
import org.jspecify.annotations.Nullable;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * {@link UvfLockedVault} backed by a parsed {@code vault.uvf} JWE.
 */
public final class UvfLockedVaultImpl implements UvfLockedVault {

	private final byte[] encoded;
	private final String json;
	private final JWEObjectJSON jwe;
	private final List<byte[]> pinnedSeedDigests;

	private UvfLockedVaultImpl(byte[] encoded, String json, JWEObjectJSON jwe, List<byte[]> pinnedSeedDigests) {
		this.encoded = encoded;
		this.json = json;
		this.jwe = jwe;
		this.pinnedSeedDigests = pinnedSeedDigests;
	}

	/**
	 * @param encoded The file contents
	 * @param json The file contents as trimmed string
	 * @return The locked vault
	 * @throws VaultConfigLoadException If the file is malformed
	 * @throws UnsupportedVaultFormatException If the file is for another UVF specification version
	 */
	public static UvfLockedVaultImpl parse(byte[] encoded, String json) throws VaultConfigLoadException, UnsupportedVaultFormatException {
		return new UvfLockedVaultImpl(encoded.clone(), json, UvfMetadataCodec.parse(json), Collections.<byte[]>emptyList());
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
	public UvfLockedVault requireSeeds(Collection<byte[]> seedDigests) {
		List<byte[]> pins = new ArrayList<>(pinnedSeedDigests);
		for (byte[] digest : seedDigests) {
			if (digest.length != Constants.SEED_DIGEST_LEN) {
				throw new IllegalArgumentException("Seed digests are " + Constants.SEED_DIGEST_LEN + " bytes long");
			}
			pins.add(digest.clone());
		}
		return new UvfLockedVaultImpl(encoded, json, jwe, Collections.unmodifiableList(pins));
	}

	@Override
	public UvfUnlockedVault unlock(CharSequence password, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException {
		Map<String, Object> header = requireRecipient(PASSWORD_KID);
		byte[] kek = Argon2Kdf.deriveKey(password, header); // the header's parameters are verified against the committed ones after decryption
		try {
			return unlock(new OctetSequenceKey.Builder(kek).keyID(PASSWORD_KID).algorithm(JWEAlgorithm.A256KW).build(), csprng);
		} finally {
			Arrays.fill(kek, (byte) 0x00);
		}
	}

	@Override
	public UvfUnlockedVault unlock(SecretKey memberKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException {
		requireRecipient(MEMBER_KEY_KID);
		return unlock(new OctetSequenceKey.Builder(memberKey).keyID(MEMBER_KEY_KID).algorithm(JWEAlgorithm.A256KW).build(), csprng);
	}

	private UvfUnlockedVault unlock(OctetSequenceKey key, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException {
		UvfSeeds seeds = decryptAndValidate(key);
		try {
			ECKey recoveryKey = recoveryPublicKey(seeds);
			return new UvfVault(seeds, jwe.getHeader(), encoded, key, recoveryKey, csprng);
		} catch (RuntimeException e) {
			seeds.destroy();
			throw e;
		}
	}

	@Override
	public UvfUnlockedVault recover(ECPrivateKey recoveryKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException {
		requireRecipient(RECOVERY_KEY_KID);
		// the public key is only known after decryption, but nimbus' ECDH decrypter only needs the private part; the pair is completed from the payload afterwards
		ECKey privateKey = new ECKey.Builder(curveOf(recoveryKey), publicKeyPlaceholder(recoveryKey)).privateKey(recoveryKey).keyID(RECOVERY_KEY_KID).build();
		UvfSeeds seeds = decryptAndValidate(privateKey);
		try {
			ECKey keyPair = new ECKey.Builder(recoveryPublicKey(seeds)).privateKey(recoveryKey).build();
			return new UvfVault(seeds, jwe.getHeader(), encoded, null, keyPair, csprng); // retains the key pair for serializedRecoveryKey()
		} catch (RuntimeException e) {
			seeds.destroy();
			throw e;
		}
	}

	@Override
	public UvfUnlockedVault recover(CharSequence recoveryKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException {
		byte[] pkcs8 = RecoveryKeys.decode(recoveryKey, true);
		try {
			return recover(RecoveryKeyPkcs8.decode(pkcs8), csprng);
		} finally {
			Arrays.fill(pkcs8, (byte) 0x00);
		}
	}

	// decrypts a fresh copy of the JWE (a JWE object can be decrypted only once), then validates recipients and seed pins as required by the specification
	private UvfSeeds decryptAndValidate(JWK key) throws VaultKeyInvalidException, VaultConfigLoadException {
		byte[] payload = UvfMetadataCodec.decrypt(UvfMetadataCodec.parse(json), key);
		UvfSeeds seeds;
		try {
			seeds = UvfSeeds.fromDecryptedPayload(new String(payload, StandardCharsets.UTF_8));
		} finally {
			Arrays.fill(payload, (byte) 0x00);
		}
		try {
			UvfMetadataCodec.validateRecipients(jwe, seeds.recipientDetails());
			for (byte[] digest : pinnedSeedDigests) {
				if (!seeds.hasSeedWithDigest(digest)) {
					throw new VaultRollbackException("vault.uvf lacks a previously seen seed, it may be outdated or forged");
				}
			}
			return seeds;
		} catch (RuntimeException e) {
			seeds.destroy();
			throw e;
		}
	}

	private Map<String, Object> requireRecipient(String kid) throws VaultConfigLoadException {
		Map<String, Object> header = UvfMetadataCodec.recipientHeader(jwe, kid);
		if (header == null) {
			throw new VaultConfigLoadException("Vault has no recipient " + kid + " (key encryption key is " + keyEncryptionKid() + ")");
		}
		return header;
	}

	// the recovery key's public key is committed in the payload; without it the vault could not be re-encrypted
	private static ECKey recoveryPublicKey(UvfSeeds seeds) throws VaultConfigLoadException {
		UvfSeeds.RecipientDetails details = seeds.recipientDetails().get(RECOVERY_KEY_KID);
		if (details == null || details.jwk == null) {
			throw new VaultConfigLoadException("Recovery key entry lacks its public key");
		}
		try {
			ECKey key = ECKey.parse(details.jwk);
			if (key.isPrivate()) {
				throw new VaultConfigLoadException("Recovery key entry must not contain private key material");
			}
			return new ECKey.Builder(key).keyID(RECOVERY_KEY_KID).algorithm(JWEAlgorithm.ECDH_ES_A256KW).build();
		} catch (ParseException e) {
			throw new VaultConfigLoadException("Malformed recovery key", e);
		}
	}

	private static Curve curveOf(ECPrivateKey key) throws VaultConfigLoadException {
		Curve curve = Curve.forECParameterSpec(key.getParams());
		if (curve == null) {
			throw new VaultConfigLoadException("Unsupported EC curve");
		}
		return curve;
	}

	// nimbus insists on a public part when building an EC JWK; ECDH-ES decryption never uses it
	private static ECPublicKey publicKeyPlaceholder(ECPrivateKey key) {
		try {
			ECParameterSpec params = key.getParams();
			KeyFactory factory = KeyFactory.getInstance("EC");
			return (ECPublicKey) factory.generatePublic(new ECPublicKeySpec(params.getGenerator(), params));
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("EC not supported by this JVM", e);
		}
	}

}
