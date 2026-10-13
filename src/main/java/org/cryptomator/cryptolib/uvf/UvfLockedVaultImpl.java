package org.cryptomator.cryptolib.uvf;

import com.nimbusds.jose.JWEObjectJSON;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.cryptomator.cryptolib.api.UvfLockedVault;
import org.cryptomator.cryptolib.api.UvfRecipient;
import org.cryptomator.cryptolib.api.UvfUnlockedVault;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.api.VaultKeyInvalidException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * {@link UvfLockedVault} backed by a parsed {@code vault.uvf} JWE.
 */
public final class UvfLockedVaultImpl implements UvfLockedVault {

	private final byte[] encoded;
	private final JWEObjectJSON jwe;
	private final List<UvfRecipientImpl> recipients;

	private UvfLockedVaultImpl(byte[] encoded, JWEObjectJSON jwe) {
		this.encoded = encoded;
		this.jwe = jwe;
		List<UvfRecipientImpl> recipients = new ArrayList<>();
		for (JWEObjectJSON.Recipient recipient : jwe.getRecipients()) {
			recipients.add(new UvfRecipientImpl(recipient));
		}
		this.recipients = Collections.unmodifiableList(recipients);
	}

	/**
	 * @param encoded The file contents
	 * @param json The file contents as trimmed string
	 * @return The locked vault
	 * @throws VaultConfigLoadException If the file is malformed
	 * @throws UnsupportedVaultFormatException If the file is for another UVF specification version
	 */
	public static UvfLockedVaultImpl parse(byte[] encoded, String json) throws VaultConfigLoadException, UnsupportedVaultFormatException {
		return new UvfLockedVaultImpl(encoded.clone(), UvfMetadataCodec.parse(json));
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
	public List<UvfRecipient> recipients() {
		return Collections.unmodifiableList(new ArrayList<UvfRecipient>(recipients));
	}

	private JWEObjectJSON.Recipient find(UvfRecipient recipient) {
		for (UvfRecipientImpl candidate : recipients) {
			if (candidate == recipient) {
				return candidate.recipient();
			}
		}
		throw new IllegalArgumentException("Recipient does not belong to this vault: " + recipient);
	}

	@Override
	public UvfUnlockedVault unlock(UvfRecipient recipient, CharSequence password, SecureRandom csprng) throws VaultKeyInvalidException, UnsupportedVaultFormatException, VaultConfigLoadException {
		return unlock(UvfMetadataCodec.unwrapWithPassword(jwe, find(recipient), password), csprng);
	}

	@Override
	public UvfUnlockedVault unlock(UvfRecipient recipient, ECPrivateKey privateKey, SecureRandom csprng) throws VaultKeyInvalidException, UnsupportedVaultFormatException, VaultConfigLoadException {
		return unlock(UvfMetadataCodec.unwrapWithPrivateKey(jwe, find(recipient), privateKey), csprng);
	}

	@Override
	public UvfUnlockedVault unlock(UvfRecipient recipient, SecretKey keyEncryptionKey, SecureRandom csprng) throws VaultKeyInvalidException, UnsupportedVaultFormatException, VaultConfigLoadException {
		return unlock(UvfMetadataCodec.unwrapWithKeyEncryptionKey(jwe, find(recipient), keyEncryptionKey), csprng);
	}

	private UvfUnlockedVault unlock(SecretKey contentKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException {
		byte[] payload = UvfMetadataCodec.decryptPayload(jwe, contentKey);
		try {
			UvfSeeds seeds = UvfSeeds.fromDecryptedPayload(new String(payload, StandardCharsets.UTF_8));
			return new UvfVault(seeds, contentKey, jwe.getHeader(), new ArrayList<>(jwe.getRecipients()), csprng);
		} finally {
			Arrays.fill(payload, (byte) 0x00);
		}
	}

}
