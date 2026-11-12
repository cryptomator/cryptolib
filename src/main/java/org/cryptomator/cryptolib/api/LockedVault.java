package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.internal.LockedVaults;

import java.security.SecureRandom;

/**
 * A parsed but not yet authenticated vault configuration file ({@code vault.cryptomator} or {@code vault.uvf}).
 * <p>
 * Nothing read from a locked vault may be trusted. Every instance is either a {@link Cvf8LockedVault} or a {@link UvfLockedVault}; the respective {@code unlock} methods authenticate the
 * configuration and yield an {@link UnlockedVault}.
 *
 * @implNote On Java 25+ this interface is {@code sealed}. Keep this file in sync with {@code src/main/java25/.../LockedVault.java}.
 */
public interface LockedVault {

	/**
	 * Parses a vault configuration file, detecting its format from the contents.
	 *
	 * @param fileContents The contents of {@code vault.cryptomator} (a compact JWT) or {@code vault.uvf} (a JWE in JSON serialization)
	 * @return A {@link Cvf8LockedVault} or a {@link UvfLockedVault}
	 * @throws VaultConfigLoadException If the contents are neither
	 */
	static LockedVault parse(byte[] fileContents) throws VaultConfigLoadException {
		return LockedVaults.parse(fileContents);
	}

	/**
	 * @return The file name under which this format stores its configuration in the vault root ({@code vault.cryptomator} or {@code vault.uvf})
	 */
	String configFileName();

	/**
	 * @return The original file contents this instance was parsed from
	 */
	byte[] encoded();

	/**
	 * Unlocks the vault with a recovery key as produced by {@link UnlockedVault#serializedRecoveryKey()}.
	 * <p>
	 * For a CVF8 vault the words are the masterkey, which is verified against the configuration's signature; persist it with a new passphrase via {@link Cvf8UnlockedVault#masterkey()}.
	 * For a UVF vault they are the private recovery key, see {@link UvfLockedVault#recover(java.security.interfaces.ECPrivateKey, SecureRandom)}; set a new password afterwards.
	 *
	 * @param recoveryKey The recovery key as words, separated by whitespace
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws IllegalArgumentException If the words are not a well-formed recovery key for this format (unknown word, wrong length, invalid checksum, ...)
	 * @throws VaultKeyInvalidException If the key does not match this vault
	 * @throws VaultConfigLoadException If the configuration is malformed
	 */
	UnlockedVault recover(CharSequence recoveryKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException;

}
