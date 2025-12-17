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
	 * Computes the directory path for the given directory metadata.
	 * @param directoryMetadata The directory metadata.
	 * @return A path relative to the vault's root (i.e. starting with `d/`).
	 * @apiNote The path contains "/" as separator and does neither start nor end with a "/".
	 */
	String dirPath(DirectoryMetadata directoryMetadata);

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
