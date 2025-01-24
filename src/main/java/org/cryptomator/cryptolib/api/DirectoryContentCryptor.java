package org.cryptomator.cryptolib.api;

public interface DirectoryContentCryptor<T extends DirectoryMetadata> {

	T rootDirectoryMetadata(); // TODO required?

	T newDirectoryMetadata();

	/**
	 * Decrypts the given directory metadata.
	 *
	 * @param ciphertext The encrypted directory metadata to decrypt.
	 * @return The decrypted directory metadata.
	 * @throws AuthenticationFailedException If the ciphertext is unauthentic.
	 */
	T decryptDirectoryMetadata(byte[] ciphertext) throws AuthenticationFailedException;

	/**
	 * Encrypts the given directory metadata.
	 *
	 * @param directoryMetadata The directory metadata to encrypt.
	 * @return The encrypted directory metadata.
	 */
	byte[] encryptDirectoryMetadata(T directoryMetadata);

	Decrypting fileNameDecryptor(T directoryMetadata);

	Encrypting fileNameEncryptor(T directoryMetadata);

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
