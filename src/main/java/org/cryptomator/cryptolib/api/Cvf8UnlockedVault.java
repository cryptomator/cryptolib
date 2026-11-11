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
	 * @param shorteningThreshold Ciphertext names with more characters than this are to be shortened, see {@link #nameShortener()}; Cryptomator uses 220
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
	 * @return The threshold of {@link #nameShortener()}: ciphertext names with more characters than this are stored shortened
	 */
	int shorteningThreshold();

}
