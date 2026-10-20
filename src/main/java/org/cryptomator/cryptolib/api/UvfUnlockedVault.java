package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.uvf.UvfVault;
import org.jspecify.annotations.Nullable;

import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;

/**
 * An unlocked Unified Vault Format vault.
 * <p>
 * Besides the operations common to all vaults, it manages the vault's seeds (key rotation) and its two recipients ({@link UvfKeyEncryptionKey}, {@link UvfRecoveryKey}), see
 * {@link UvfLockedVault}. Changes become effective once {@link #serializeConfig()} is written back. Replacing a recipient requires {@link #addSeed() a new seed} before the
 * configuration can be serialized: the previous secret's holder knows all existing seeds.
 */
public interface UvfUnlockedVault extends UnlockedVault {

	/**
	 * Creates a new vault with a fresh KDF salt and initial seed for the given recipients.
	 * <p>
	 * Persist the result with {@link #serializeConfig()}, then create the root directory with {@link VaultDirectory#writeMetadataBackup(VaultWriter)}.
	 *
	 * @param csprng A cryptographically secure random number generator used for seeds, nonces, keys and directory ids
	 * @param keyEncryptionKey The password or member key; a password is turned into the key encryption key immediately and not retained
	 * @param recoveryKey The recovery key; its private part, if present, is retained for {@link #serializedRecoveryKey()}
	 * @return The new, unlocked vault
	 */
	static UvfUnlockedVault create(SecureRandom csprng, UvfKeyEncryptionKey keyEncryptionKey, UvfRecoveryKey recoveryKey) {
		return UvfVault.create(csprng, keyEncryptionKey, recoveryKey);
	}

	/**
	 * Serializes the configuration, encrypting the metadata with a fresh content key for both recipients.
	 * <p>
	 * If nothing changed since the vault was unlocked or last serialized, the previous serialization is returned, so writing it back is unnecessary.
	 *
	 * @return The contents of {@code vault.uvf}
	 * @throws IllegalStateException If no password or member key or no recovery key is set, or if a key was replaced without {@link #addSeed() adding a seed} afterwards
	 */
	@Override
	byte[] serializeConfig();

	/**
	 * @return Fields of the decrypted vault metadata that cryptolib does not interpret (e.g. vendor-specific fields); preserved by {@link #serializeConfig()} (unmodifiable)
	 */
	Map<String, @Nullable Object> customFields();

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
	 * Computes the digest of every seed, from which its id is derived, for seed pinning: persist them outside the vault and pass them to {@link UvfLockedVault#requireSeeds(java.util.Collection)}
	 * on the next unlock.
	 *
	 * @return The 32 byte digest of each seed by seed id (unmodifiable)
	 */
	Map<Integer, byte[]> seedDigests();

	/**
	 * Rotates the key: adds a fresh random seed and makes it the latest one, so that new files and directories use keys derived from it.
	 * <p>
	 * Required after replacing a password, member key or recovery key, since the previous secret's holder knows all existing seeds; {@link #serializeConfig()} refuses to serialize otherwise.
	 *
	 * @return The id of the new seed
	 */
	int addSeed();

	/**
	 * @return {@link UvfLockedVault#PASSWORD_KID}, {@link UvfLockedVault#MEMBER_KEY_KID}, or {@code null} after {@link UvfLockedVault#recover(java.security.interfaces.ECPrivateKey, SecureRandom)} until {@link #setKeyEncryptionKey(UvfKeyEncryptionKey)} is called
	 */
	@Nullable String keyEncryptionKid();

	/**
	 * Replaces the password or member key. A password is turned into the key encryption key immediately, with a fresh salt, and not retained.
	 * <p>
	 * The previous secret's holder knows all existing seeds, so {@link #addSeed()} must be called before the vault can be serialized again.
	 *
	 * @param keyEncryptionKey The new password or member key
	 */
	void setKeyEncryptionKey(UvfKeyEncryptionKey keyEncryptionKey);

	/**
	 * Replaces the recovery key. The private part, if present, is retained for {@link #serializedRecoveryKey()}; as a JCA object it is dropped on {@link #destroy()} but cannot be zeroed.
	 * <p>
	 * The previous key's holder knows all existing seeds, so {@link #addSeed()} must be called before the vault can be serialized again.
	 *
	 * @param recoveryKey The new recovery key
	 */
	void setRecoveryKey(UvfRecoveryKey recoveryKey);

}
