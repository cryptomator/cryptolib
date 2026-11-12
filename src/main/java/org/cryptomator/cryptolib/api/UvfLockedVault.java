package org.cryptomator.cryptolib.api;

import org.jspecify.annotations.Nullable;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.util.Collection;

/**
 * A parsed but not yet decrypted {@code vault.uvf} file (Unified Vault Format).
 * <p>
 * A vault has two recipients: a key encryption key, which is either derived from a password ({@value #PASSWORD_KID}) or a member key supplied by Cryptomator Hub ({@value #MEMBER_KEY_KID}),
 * and an EC recovery key ({@value #RECOVERY_KEY_KID}). Algorithms and the recovery key's public key are part of the encrypted payload ({@code recipientDetails}) and verified against
 * the unprotected recipient headers on unlock, as are the seeds (their ids are derived from them). Applications should additionally pin seeds, see {@link #requireSeeds(Collection)}.
 */
public interface UvfLockedVault extends LockedVault {

	/** Key id of the password-based ({@code A256KW} with an Argon2id-derived key) recipient. */
	String PASSWORD_KID = "org.cryptomator.password.argon2";
	/** Key id of the member key ({@code A256KW}) recipient. */
	String MEMBER_KEY_KID = "org.cryptomator.hub.memberkey";
	/** Key id of the recovery key ({@code ECDH-ES+A256KW}) recipient. */
	String RECOVERY_KEY_KID = "org.cryptomator.recoverykey";

	/**
	 * @return The UVF specification version claimed by the protected header (unverified)
	 */
	int allegedSpecVersion();

	/**
	 * @return {@link #PASSWORD_KID} or {@link #MEMBER_KEY_KID}, telling the application which secret to ask for; {@code null} if the file has neither entry (unverified)
	 */
	@Nullable String keyEncryptionKid();

	/**
	 * Returns a view of this vault that refuses to unlock unless every pinned seed is present, protecting against an outdated or forged {@code vault.uvf}.
	 * <p>
	 * Applications persist the {@link UvfUnlockedVault#seedDigests() seed digests} of every vault they have unlocked outside the vault storage and pass them here on the next unlock. A
	 * {@code vault.uvf} that lacks a seed with one of these digests makes every {@code unlock} and {@code recover} method throw a {@link VaultRollbackException}.
	 *
	 * @param seedDigests 32 byte seed digests the file must contain
	 * @return A locked vault enforcing the pins (this instance is unchanged)
	 */
	UvfLockedVault requireSeeds(Collection<byte[]> seedDigests);

	/**
	 * Unlocks a password-protected vault.
	 *
	 * @param password The password
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws VaultKeyInvalidException If the password is wrong
	 * @throws VaultRollbackException If a {@link #requireSeeds(Collection) pinned} seed is missing
	 * @throws VaultConfigLoadException If the vault has no {@link #PASSWORD_KID} entry or the configuration is malformed or inconsistent
	 */
	UvfUnlockedVault unlock(CharSequence password, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException;

	/**
	 * Unlocks a vault with its member key.
	 *
	 * @param memberKey The 256 bit AES key for the {@link #MEMBER_KEY_KID} entry
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws VaultKeyInvalidException If the key is wrong
	 * @throws VaultRollbackException If a {@link #requireSeeds(Collection) pinned} seed is missing
	 * @throws VaultConfigLoadException If the vault has no {@link #MEMBER_KEY_KID} entry or the configuration is malformed or inconsistent
	 */
	UvfUnlockedVault unlock(SecretKey memberKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException;

	/**
	 * Unlocks a vault with its recovery key, e.g. to set a new password with {@link UvfUnlockedVault#setKeyEncryptionKey(UvfKeyEncryptionKey)}.
	 * <p>
	 * The result has no key encryption key: {@link UvfUnlockedVault#setKeyEncryptionKey(UvfKeyEncryptionKey)} and {@link UvfUnlockedVault#addSeed()} must be called before it can be serialized.
	 * It retains the recovery key pair, so {@link UvfUnlockedVault#serializedRecoveryKey()} is available.
	 *
	 * @param recoveryKey The private key matching the {@link #RECOVERY_KEY_KID recovery key entry}
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws VaultKeyInvalidException If the key is wrong
	 * @throws VaultRollbackException If a {@link #requireSeeds(Collection) pinned} seed is missing
	 * @throws VaultConfigLoadException If the vault has no recovery key entry or the configuration is malformed or inconsistent
	 */
	UvfUnlockedVault recover(ECPrivateKey recoveryKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException;

	/**
	 * Unlocks a vault with its recovery key encoded as words, see {@link #recover(ECPrivateKey, SecureRandom)} and {@link LockedVault#recover(CharSequence, SecureRandom)}.
	 *
	 * @param recoveryKey The words
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws IllegalArgumentException If the words are not a well-formed UVF recovery key (a P-384 private key)
	 * @throws VaultKeyInvalidException If the key is wrong
	 * @throws VaultRollbackException If a {@link #requireSeeds(Collection) pinned} seed is missing
	 * @throws VaultConfigLoadException If the vault has no recovery key entry or the configuration is malformed or inconsistent
	 */
	@Override
	UvfUnlockedVault recover(CharSequence recoveryKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException;

}
