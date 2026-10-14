package org.cryptomator.cryptolib.api;

import org.jspecify.annotations.Nullable;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;

/**
 * A parsed but not yet decrypted {@code vault.uvf} file (Unified Vault Format).
 * <p>
 * A vault has two recipients: a key encryption key, which is either derived from a password ({@value #PASSWORD_KID}) or a member key supplied by Cryptomator Hub ({@value #MEMBER_KEY_KID}),
 * and an EC recovery key ({@value #RECOVERY_KEY_KID_PREFIX} followed by the key's JWK thumbprint).
 */
public interface UvfLockedVault extends LockedVault {

	/** Key id of the password-based ({@code A256KW} with an Argon2id-derived key) recipient. */
	String PASSWORD_KID = "org.cryptomator.password.argon2";
	/** Key id of the member key ({@code A256KW}) recipient. */
	String MEMBER_KEY_KID = "org.cryptomator.hub.memberkey";
	/** Key id prefix of the recovery key ({@code ECDH-ES+A256KW}) recipient. */
	String RECOVERY_KEY_KID_PREFIX = "org.cryptomator.hub.recoverykey."; // TODO: rename to org.cryptomator.recoverykey.* eventually?

	/**
	 * @return The UVF specification version claimed by the protected header (unverified)
	 */
	int allegedSpecVersion();

	/**
	 * @return {@link #PASSWORD_KID} or {@link #MEMBER_KEY_KID}, telling the application which secret to ask for; {@code null} if the file has neither entry (unverified)
	 */
	@Nullable String keyEncryptionKid();

	/**
	 * @return The key id of the recovery key entry, {@link #RECOVERY_KEY_KID_PREFIX} followed by the key's JWK thumbprint; {@code null} if the file has no such entry (unverified)
	 */
	@Nullable String recoveryKid();

	/**
	 * Unlocks a password-protected vault.
	 *
	 * @param password The password
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws VaultKeyInvalidException If the password is wrong
	 * @throws VaultConfigLoadException If the vault has no {@link #PASSWORD_KID} entry or the configuration is malformed
	 */
	UvfUnlockedVault unlock(CharSequence password, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException;

	/**
	 * Unlocks a vault with its member key.
	 *
	 * @param memberKey The 256 bit AES key for the {@link #MEMBER_KEY_KID} entry
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws VaultKeyInvalidException If the key is wrong
	 * @throws VaultConfigLoadException If the vault has no {@link #MEMBER_KEY_KID} entry or the configuration is malformed
	 */
	UvfUnlockedVault unlock(SecretKey memberKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException;

	/**
	 * Unlocks a vault with its recovery key, e.g. to set a new password with {@link UvfUnlockedVault#setPassword(CharSequence)}.
	 * <p>
	 * The result has no key encryption key: {@link UvfUnlockedVault#setPassword(CharSequence)} or {@link UvfUnlockedVault#setMemberKey(SecretKey)} must be called before it can be serialized.
	 *
	 * @param recoveryKey The private key matching the {@link #recoveryKid() recovery key entry}
	 * @param csprng A cryptographically secure random number generator used for nonces, new keys, seeds and directory ids
	 * @return The unlocked vault
	 * @throws VaultKeyInvalidException If the key is wrong
	 * @throws VaultConfigLoadException If the vault has no recovery key entry or the configuration is malformed
	 */
	UvfUnlockedVault recover(ECPrivateKey recoveryKey, SecureRandom csprng) throws VaultKeyInvalidException, VaultConfigLoadException;

}
