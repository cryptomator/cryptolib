package org.cryptomator.cryptolib.api;

public interface DirectoryContentCryptor {

	DirectoryMetadata rootDirectoryMetadata();

	DirectoryMetadata newDirectoryMetadata();

	/**
	 * Decrypts the given directory metadata.
	 *
	 * @param ciphertext The encrypted directory metadata to decrypt.
	 * @return The decrypted directory metadata.
	 * @throws AuthenticationFailedException If the ciphertext is unauthentic.
	 * @apiNote In Universal Vault Format, {@code dir.uvf} exists twice: in the parent directory (used for traversal) and in the directory itself (used for recovery only).
	 * When recovering from the latter, callers must verify that {@link #dirPath(DirectoryMetadata)} of the result equals the path the copy was found under.
	 */
	DirectoryMetadata decryptDirectoryMetadata(byte[] ciphertext) throws AuthenticationFailedException;

	/**
	 * Encrypts the given directory metadata.
	 *
	 * @param directoryMetadata The directory metadata to encrypt.
	 * @return The encrypted directory metadata.
	 */
	byte[] encryptDirectoryMetadata(DirectoryMetadata directoryMetadata);

	/**
	 * Encrypts a symlink target into the contents of a symlink metadata file ({@code symlink.uvf}).
	 *
	 * @param target The cleartext symlink target
	 * @return The encrypted symlink metadata, using the latest seed
	 * @throws UnsupportedOperationException If the vault format stores symlink targets as regular file content
	 * @apiNote Only relevant for Universal Vault Format, where symlink metadata is encrypted under a dedicated header key. Cryptomator Vault Format encrypts symlink targets like regular files.
	 */
	default byte[] encryptSymlinkTarget(String target) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Decrypts the contents of a symlink metadata file ({@code symlink.uvf}).
	 *
	 * @param ciphertext The encrypted symlink metadata
	 * @return The cleartext symlink target, stored verbatim and therefore untrusted: callers should validate it and warn the user if it points outside the vault
	 * @throws AuthenticationFailedException If the ciphertext is unauthentic
	 * @throws UnsupportedOperationException If the vault format stores symlink targets as regular file content
	 * @apiNote Only relevant for Universal Vault Format, see {@link #encryptSymlinkTarget(String)}
	 */
	default String decryptSymlinkTarget(byte[] ciphertext) throws AuthenticationFailedException {
		throw new UnsupportedOperationException();
	}

	/**
	 * Computes the directory path for the given directory metadata.
	 * @param directoryMetadata The directory metadata.
	 * @return A path relative to the vault's root (i.e. starting with `d/`).
	 * @apiNote The path contains "/" as separator and does neither start nor end with a "/".
	 */
	String dirPath(DirectoryMetadata directoryMetadata);

	/**
	 * @param directoryMetadata The directory metadata.
	 * @return A decryptor for the names of this directory's children
	 * @apiNote In Universal Vault Format, the decryptor rejects names that are empty, {@code .}, {@code ..} or contain {@code /} or NUL.
	 * Names that are invalid on the local file system (e.g. containing {@code \} or {@code :}) must be rejected by the caller.
	 */
	Decrypting fileNameDecryptor(DirectoryMetadata directoryMetadata);

	Encrypting fileNameEncryptor(DirectoryMetadata directoryMetadata);

	@FunctionalInterface
	interface Decrypting {
		/**
		 * Decrypts a single filename
		 *
		 * @param ciphertext the full filename to decrypt, including the file extension
		 * @return Plaintext
		 * @throws AuthenticationFailedException If the ciphertext is unauthentic.
		 * @throws IllegalArgumentException      If the filename does not meet the expected format.
		 */
		String decrypt(String ciphertext) throws AuthenticationFailedException, IllegalArgumentException;
	}

	@FunctionalInterface
	interface Encrypting {
		/**
		 * Encrypts a single filename
		 *
		 * @param plaintext the full filename to encrypt, including the file extension
		 * @return Ciphertext
		 */
		String encrypt(String plaintext);
	}

}
