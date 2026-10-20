package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.uvf.UvfVault;
import org.jspecify.annotations.Nullable;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import java.util.Set;

/**
 * An unlocked Unified Vault Format vault.
 * <p>
 * Besides the operations common to all vaults, it manages the vault's seeds (key rotation) and its two recipients, see {@link UvfLockedVault}. Changes become effective once
 * {@link #serializeConfig()} is written back. Replacing a password, member key or recovery key requires {@link #addSeed() a new seed} before the configuration can be serialized: the
 * previous secret's holder knows all existing seeds.
 */
public interface UvfUnlockedVault extends UnlockedVault {

	/**
	 * Creates a new vault with a fresh KDF salt and initial seed.
	 * <p>
	 * Set a password or member key and a recovery key before persisting the result with {@link #serializeConfig()}, then create the root directory with
	 * {@link VaultDirectory#writeMetadataBackup(VaultWriter)}.
	 *
	 * @param csprng A cryptographically secure random number generator used for seeds, nonces, keys and directory ids
	 * @return The new, unlocked vault
	 */
	static UvfUnlockedVault create(SecureRandom csprng) {
		return UvfVault.create(csprng);
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
	 * @return {@link UvfLockedVault#PASSWORD_KID}, {@link UvfLockedVault#MEMBER_KEY_KID}, or {@code null} after {@link UvfLockedVault#recover(java.security.interfaces.ECPrivateKey, SecureRandom)} until a new one is set
	 */
	@Nullable String keyEncryptionKid();

	/**
	 * Protects the vault with a password using {@link Argon2Params#DEFAULT}, replacing a previous password or member key.
	 * <p>
	 * The key encryption key is derived immediately, with a fresh salt; the password itself is not retained. Call {@link #addSeed()} before serializing when replacing a secret.
	 *
	 * @param password The password
	 */
	void setPassword(CharSequence password);

	/**
	 * Protects the vault with a password, replacing a previous password or member key.
	 * <p>
	 * The key encryption key is derived immediately, with a fresh salt; the password itself is not retained. Call {@link #addSeed()} before serializing when replacing a secret.
	 *
	 * @param password The password
	 * @param params Argon2id cost parameters
	 */
	void setPassword(CharSequence password, Argon2Params params);

	/**
	 * Protects the vault with a member key, replacing a previous password or member key. Call {@link #addSeed()} before serializing when replacing a secret.
	 *
	 * @param memberKey A 256 bit AES key; the caller remains responsible for destroying it
	 */
	void setMemberKey(SecretKey memberKey);

	/**
	 * Generates a key pair suitable for {@link #setRecoveryKey(KeyPair)}.
	 *
	 * @param csprng A cryptographically secure random number generator
	 * @return A fresh P-384 key pair
	 */
	static KeyPair generateRecoveryKey(SecureRandom csprng) {
		return UvfVault.generateRecoveryKey(csprng);
	}

	/**
	 * Sets the recovery key, replacing a previous one. Call {@link #addSeed()} before serializing when replacing a key.
	 * <p>
	 * The vault retains the key pair, so that {@link #serializedRecoveryKey()} can encode it for the user. The private key is dropped on {@link #destroy()}, but as a JCA object it cannot be
	 * zeroed.
	 *
	 * @param recoveryKey A P-384 key pair, see {@link #generateRecoveryKey(SecureRandom)}
	 * @throws IllegalArgumentException If the pair is not a P-384 EC key pair
	 */
	void setRecoveryKey(KeyPair recoveryKey);

	/**
	 * Sets the recovery key by its public part only, replacing a previous one. Call {@link #addSeed()} before serializing when replacing a key.
	 * <p>
	 * {@link #serializedRecoveryKey()} is unavailable afterwards, as the vault does not know the private key.
	 *
	 * @param recoveryKey The public key (P-256, P-384 or P-521) whose private counterpart {@link UvfLockedVault#recover(java.security.interfaces.ECPrivateKey, SecureRandom) recovers} the vault
	 */
	void setRecoveryKey(ECPublicKey recoveryKey);

}
