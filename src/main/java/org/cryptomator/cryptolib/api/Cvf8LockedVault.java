package org.cryptomator.cryptolib.api;

import java.net.URI;
import java.security.SecureRandom;

/**
 * A parsed but not yet authenticated {@code vault.cryptomator} file (Cryptomator Vault Format 8).
 */
public interface Cvf8LockedVault extends LockedVault {

	/**
	 * @return The id of the masterkey required to unlock this vault, e.g. {@code masterkeyfile:masterkey.cryptomator} (unverified)
	 */
	URI keyId();

	/**
	 * @return The vault format version claimed by the configuration (unverified)
	 */
	int allegedFormatVersion();

	/**
	 * @return The name shortening threshold claimed by the configuration (unverified)
	 */
	int allegedShorteningThreshold();

	/**
	 * Verifies the configuration's signature with the given masterkey and unlocks the vault.
	 * <p>
	 * The returned vault holds its own copy of the key; the caller remains responsible for destroying {@code masterkey}.
	 *
	 * @param masterkey The masterkey identified by {@link #keyId()}
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys and directory ids
	 * @return The unlocked vault
	 * @throws VaultKeyInvalidException If the signature does not verify with this key
	 * @throws UnsupportedVaultFormatException If the configuration is for a vault format version other than 8
	 * @throws VaultConfigLoadException If the configuration is malformed
	 */
	Cvf8UnlockedVault unlock(CvfMasterkey masterkey, SecureRandom csprng) throws VaultKeyInvalidException, UnsupportedVaultFormatException, VaultConfigLoadException;

	/**
	 * Loads the masterkey for {@link #keyId()} via the given loader and unlocks the vault.
	 * <p>
	 * The loaded key is destroyed after use.
	 *
	 * @param keyLoader Resolves {@link #keyId()} to a masterkey
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys and directory ids
	 * @return The unlocked vault
	 * @throws MasterkeyLoadingFailedException If the loader can not provide the key
	 * @throws VaultKeyInvalidException If the signature does not verify with the loaded key
	 * @throws UnsupportedVaultFormatException If the configuration is for a vault format version other than 8
	 * @throws VaultConfigLoadException If the configuration is malformed
	 */
	Cvf8UnlockedVault unlock(MasterkeyLoader keyLoader, SecureRandom csprng) throws MasterkeyLoadingFailedException, VaultKeyInvalidException, UnsupportedVaultFormatException, VaultConfigLoadException;

}
