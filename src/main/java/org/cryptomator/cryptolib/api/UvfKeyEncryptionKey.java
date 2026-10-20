package org.cryptomator.cryptolib.api;

import org.jspecify.annotations.Nullable;

import javax.crypto.SecretKey;

/**
 * The key encryption key recipient of a UVF vault: either a password, from which the key is derived with Argon2id, or a member key supplied by Cryptomator Hub.
 * <p>
 * Instances are plain holders for {@link UvfUnlockedVault#create(java.security.SecureRandom, UvfKeyEncryptionKey, UvfRecoveryKey)} and
 * {@link UvfUnlockedVault#setKeyEncryptionKey(UvfKeyEncryptionKey)}; the vault derives and retains the key, never the password.
 */
public final class UvfKeyEncryptionKey {

	private static final int MEMBER_KEY_LEN = 32;

	private final String kid;
	private final @Nullable CharSequence password;
	private final @Nullable Argon2Params argon2Params;
	private final @Nullable SecretKey memberKey;

	private UvfKeyEncryptionKey(String kid, @Nullable CharSequence password, @Nullable Argon2Params argon2Params, @Nullable SecretKey memberKey) {
		this.kid = kid;
		this.password = password;
		this.argon2Params = argon2Params;
		this.memberKey = memberKey;
	}

	/**
	 * A password with {@link Argon2Params#DEFAULT} cost parameters.
	 *
	 * @param password The password; the caller remains responsible for it, the vault only retains the derived key
	 * @return The recipient ({@link UvfLockedVault#PASSWORD_KID})
	 */
	public static UvfKeyEncryptionKey password(CharSequence password) {
		return password(password, Argon2Params.DEFAULT);
	}

	/**
	 * A password with the given cost parameters.
	 *
	 * @param password The password; the caller remains responsible for it, the vault only retains the derived key
	 * @param argon2Params Argon2id cost parameters for deriving the key
	 * @return The recipient ({@link UvfLockedVault#PASSWORD_KID})
	 */
	public static UvfKeyEncryptionKey password(CharSequence password, Argon2Params argon2Params) {
		return new UvfKeyEncryptionKey(UvfLockedVault.PASSWORD_KID, password, argon2Params, null);
	}

	/**
	 * A member key as issued by Cryptomator Hub.
	 *
	 * @param memberKey A 256 bit AES key; the caller remains responsible for destroying it, the vault keeps a copy
	 * @return The recipient ({@link UvfLockedVault#MEMBER_KEY_KID})
	 * @throws IllegalArgumentException If the key is not a 256 bit key with encoding
	 */
	public static UvfKeyEncryptionKey memberKey(SecretKey memberKey) {
		byte[] encoded = memberKey.getEncoded();
		if (encoded == null || encoded.length != MEMBER_KEY_LEN) {
			throw new IllegalArgumentException("Member key must be a 256 bit AES key");
		}
		return new UvfKeyEncryptionKey(UvfLockedVault.MEMBER_KEY_KID, null, null, memberKey);
	}

	/**
	 * @return {@link UvfLockedVault#PASSWORD_KID} or {@link UvfLockedVault#MEMBER_KEY_KID}
	 */
	public String kid() {
		return kid;
	}

	/**
	 * @return The password, if this is a password recipient
	 */
	public @Nullable CharSequence password() {
		return password;
	}

	/**
	 * @return The Argon2id cost parameters, if this is a password recipient
	 */
	public @Nullable Argon2Params argon2Params() {
		return argon2Params;
	}

	/**
	 * @return The member key, if this is a member key recipient
	 */
	public @Nullable SecretKey memberKey() {
		return memberKey;
	}

}
