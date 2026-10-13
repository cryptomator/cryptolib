package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.cvf8.Cvf8Vault;

import java.net.URI;
import java.security.SecureRandom;

/**
 * An unlocked Cryptomator Vault Format 8 vault.
 */
public interface Cvf8UnlockedVault extends UnlockedVault {

	/**
	 * Creates the configuration for a new vault. New vaults always use {@link CipherCombo#SIV_GCM} and the key id {@code masterkeyfile:masterkey.cryptomator}.
	 * <p>
	 * The returned vault holds its own copy of the key; the caller remains responsible for destroying {@code masterkey}. Persist the result with {@link #serializeConfig()} and create the
	 * root directory with {@link VaultDirectory#writeMetadataBackup(VaultWriter)}.
	 *
	 * @param masterkey The vault's masterkey
	 * @param shorteningThreshold Ciphertext names longer than this are shortened; Cryptomator uses 220
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys and directory ids
	 * @return The new, unlocked vault
	 */
	static Cvf8UnlockedVault create(CvfMasterkey masterkey, int shorteningThreshold, SecureRandom csprng) {
		return Cvf8Vault.create(masterkey, shorteningThreshold, csprng);
	}

	/**
	 * @return The vault's masterkey (a live view, destroyed together with the vault)
	 */
	CvfMasterkey masterkey();

	/**
	 * @return The vault's unique id ({@code jti} claim)
	 */
	String vaultId();

	/**
	 * @return The id of the masterkey this vault was created with, e.g. {@code masterkeyfile:masterkey.cryptomator}
	 */
	URI keyId();

	/**
	 * @return The cipher combination used by this vault
	 */
	CipherCombo cipherCombo();

	/**
	 * @return Ciphertext names longer than this are stored shortened
	 */
	int shorteningThreshold();

	/**
	 * Checks whether a name found on disk is a shortened name ({@code *.c9s}).
	 *
	 * @param nameOnDisk A ciphertext node name
	 * @return {@code true} if the name is shortened and the inflated name must be read from its {@code name.c9s} file
	 */
	boolean isShortenedName(String nameOnDisk);

	/**
	 * Computes the shortened form of a ciphertext name, regardless of the {@link #shorteningThreshold()}.
	 *
	 * @param ciphertextName A full ciphertext name including the {@code .c9r} extension
	 * @return The {@code *.c9s} name
	 */
	String shortenName(String ciphertextName);

}
