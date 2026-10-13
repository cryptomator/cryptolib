package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.uvf.UvfVault;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * An unlocked Unified Vault Format vault.
 * <p>
 * Besides the operations common to all vaults, it manages the vault's seeds (key rotation) and recipients. Changes become effective once {@link #serializeConfig()} is written back.
 */
public interface UvfUnlockedVault extends UnlockedVault {

	/**
	 * Creates a new vault with a fresh KDF salt and initial seed and no recipients yet.
	 * <p>
	 * Add at least one recipient before persisting the result with {@link #serializeConfig()}, then create the root directory with {@link VaultDirectory#writeMetadataBackup(VaultWriter)}.
	 *
	 * @param csprng A cryptographically secure random number generator used for seeds, nonces, keys and directory ids
	 * @return The new, unlocked vault
	 */
	static UvfUnlockedVault create(SecureRandom csprng) {
		return UvfVault.create(csprng);
	}

	/**
	 * @return The recipients that can unlock this vault, in file order
	 */
	List<UvfRecipient> recipients();

	/**
	 * @return Fields of the decrypted vault metadata that cryptolib does not interpret (e.g. vendor-specific fields); preserved by {@link #serializeConfig()} (unmodifiable)
	 */
	Map<String, Object> customFields();

	/**
	 * @return The id of the seed the vault was created with
	 */
	int initialSeedId();

	/**
	 * @return The id of the seed used for newly created files and directories
	 */
	int latestSeedId();

	/**
	 * @return The ids of all seeds known to this vault (unmodifiable)
	 */
	Set<Integer> seedIds();

	/**
	 * Rotates the key: adds a fresh random seed and makes it the latest one, so that new files and directories use keys derived from it.
	 *
	 * @return The id of the new seed
	 */
	int addSeed();

	/**
	 * Adds a password-based recipient ({@code PBES2-HS512+A256KW}).
	 *
	 * @param kid Key id for the new recipient; should use an application-specific reverse-DNS prefix
	 * @param password The recipient's password
	 * @param iterationCount PBKDF2 iteration count ({@code p2c}); at least 1000, at most 1,000,000
	 */
	void addPasswordRecipient(String kid, CharSequence password, int iterationCount);

	/**
	 * Adds a recipient identified by an EC public key ({@code ECDH-ES+A256KW}).
	 *
	 * @param kid Key id for the new recipient; should use an application-specific reverse-DNS prefix
	 * @param publicKey The recipient's EC public key (P-256, P-384 or P-521)
	 */
	void addEcdhRecipient(String kid, ECPublicKey publicKey);

	/**
	 * Adds a recipient whose key encryption key was derived elsewhere ({@code A256KW}).
	 *
	 * @param kid Key id for the new recipient; should use an application-specific reverse-DNS prefix
	 * @param keyEncryptionKey A 256 bit AES key
	 */
	void addKeyWrapRecipient(String kid, SecretKey keyEncryptionKey);

	/**
	 * Removes a recipient's entry.
	 * <p>
	 * This does not revoke the recipient's access to existing data: it already knows the content encryption key and all existing seeds. To follow the UVF specification, callers must
	 * afterwards {@link #addSeed() add a new seed} and re-add all remaining recipients, which cryptolib can not do on its own because it does not hold their secrets or public keys.
	 *
	 * @param kid Key id of the recipient to remove
	 * @throws IllegalArgumentException If no recipient with this id exists
	 * @throws IllegalStateException If this is the last recipient
	 */
	void removeRecipient(String kid);

}
