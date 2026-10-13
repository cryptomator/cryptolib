package org.cryptomator.cryptolib.api;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.List;

/**
 * A parsed but not yet decrypted {@code vault.uvf} file (Unified Vault Format).
 */
public interface UvfLockedVault extends LockedVault {

	/**
	 * @return The UVF specification version claimed by the protected header (unverified)
	 */
	int allegedSpecVersion();

	/**
	 * @return The recipients listed in the configuration, in file order (unverified)
	 */
	List<UvfRecipient> recipients();

	/**
	 * Unlocks the vault as a password-based recipient ({@code PBES2-HS256+A128KW}, {@code PBES2-HS384+A192KW} or {@code PBES2-HS512+A256KW}).
	 *
	 * @param recipient One of {@link #recipients()} using a PBES2 algorithm
	 * @param password The recipient's password
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws VaultKeyInvalidException If the password is wrong
	 * @throws UnsupportedVaultFormatException If the configuration is for an unsupported UVF specification version
	 * @throws VaultConfigLoadException If the configuration is malformed or the recipient's algorithm does not match
	 */
	UvfUnlockedVault unlock(UvfRecipient recipient, CharSequence password, SecureRandom csprng) throws VaultKeyInvalidException, UnsupportedVaultFormatException, VaultConfigLoadException;

	/**
	 * Unlocks the vault as an ECDH-ES recipient ({@code ECDH-ES+A128KW}, {@code ECDH-ES+A192KW} or {@code ECDH-ES+A256KW}).
	 *
	 * @param recipient One of {@link #recipients()} using an ECDH-ES key wrapping algorithm
	 * @param privateKey The recipient's EC private key
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws VaultKeyInvalidException If the private key does not match
	 * @throws UnsupportedVaultFormatException If the configuration is for an unsupported UVF specification version
	 * @throws VaultConfigLoadException If the configuration is malformed or the recipient's algorithm does not match
	 */
	UvfUnlockedVault unlock(UvfRecipient recipient, ECPrivateKey privateKey, SecureRandom csprng) throws VaultKeyInvalidException, UnsupportedVaultFormatException, VaultConfigLoadException;

	/**
	 * Unlocks the vault as a recipient whose key encryption key was derived elsewhere ({@code A128KW}, {@code A192KW} or {@code A256KW}).
	 *
	 * @param recipient One of {@link #recipients()} using an AES key wrapping algorithm
	 * @param keyEncryptionKey The recipient's AES key encryption key
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws VaultKeyInvalidException If the key does not match
	 * @throws UnsupportedVaultFormatException If the configuration is for an unsupported UVF specification version
	 * @throws VaultConfigLoadException If the configuration is malformed or the recipient's algorithm does not match
	 */
	UvfUnlockedVault unlock(UvfRecipient recipient, SecretKey keyEncryptionKey, SecureRandom csprng) throws VaultKeyInvalidException, UnsupportedVaultFormatException, VaultConfigLoadException;

}
