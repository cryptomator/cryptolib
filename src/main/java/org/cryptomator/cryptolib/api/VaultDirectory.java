package org.cryptomator.cryptolib.api;

import java.io.IOException;

/**
 * One directory of a vault, identified by its directory id (and, for UVF, the key revision it was created with).
 * <p>
 * A directory knows where its contents are stored ({@link #dirPath()}) and encrypts or decrypts the names of its children. Instances are immutable and compare equal if they refer to
 * the same directory.
 */
public interface VaultDirectory {

	/**
	 * @return A copy of the raw directory id
	 */
	byte[] dirId();

	/**
	 * @return The path of the directory holding this directory's content, relative to the vault root, e.g. {@code d/AB/CDEFGHIJKLMNOPQRSTUVWXYZ234567}; uses {@code /} as separator
	 */
	String dirPath();

	/**
	 * @return The 32 character hash of the directory id that forms the last two path components of {@link #dirPath()}
	 */
	String dirHash();

	/**
	 * @return The path of the backup copy of this directory's metadata ({@code dirid.c9r} / {@code dir.uvf}) inside {@link #dirPath()}, relative to the vault root
	 */
	String backupFilePath();

	/**
	 * Produces the contents of the {@code dir.c9r} / {@code dir.uvf} file that a parent's node directory uses to point at this directory.
	 *
	 * @return The directory file contents; for UVF a fresh, independent ciphertext on every call
	 */
	byte[] encryptedMetadata();

	/**
	 * Produces the contents of the backup copy of this directory's metadata stored at {@link #backupFilePath()}.
	 *
	 * @return The backup file contents; for UVF a fresh, independent ciphertext on every call
	 */
	byte[] encryptedMetadataBackup();

	/**
	 * Writes the backup copy of this directory's metadata to {@link #backupFilePath()}, which also creates the directory's content directory. This is how a vault's root directory is created.
	 *
	 * @param writer Writes files into the vault
	 * @throws IOException If the writer fails
	 */
	void writeMetadataBackup(VaultWriter writer) throws IOException;

	/**
	 * Encrypts the name of a child of this directory. The result is deterministic.
	 *
	 * @param cleartextName The child's cleartext name
	 * @return The child's node, including its name on disk and the layout of its well-known files
	 */
	VaultNode encryptName(String cleartextName);

	/**
	 * Decrypts the name of a child found inside {@link #dirPath()}, inflating shortened names through the given reader when necessary.
	 *
	 * @param nameOnDisk The child's node name as listed in the file system
	 * @param reader Reads the child's {@code name.c9s} file if the name is shortened
	 * @return The child's cleartext name
	 * @throws IOException If the reader fails
	 * @throws AuthenticationFailedException If the name is unauthentic or does not belong to this directory
	 * @throws IllegalArgumentException If {@code nameOnDisk} is not a ciphertext node name (e.g. {@code dirid.c9r})
	 */
	String decryptName(String nameOnDisk, VaultReader reader) throws IOException, AuthenticationFailedException;

	/**
	 * Decrypts a full ciphertext name of a child of this directory.
	 *
	 * @param ciphertextName The child's full ciphertext name including the extension ({@code *.c9r} / {@code *.uvf}); for shortened nodes the contents of {@code name.c9s}
	 * @return The child's cleartext name
	 * @throws AuthenticationFailedException If the name is unauthentic or does not belong to this directory
	 * @throws IllegalArgumentException If {@code ciphertextName} is not a ciphertext node name
	 */
	String decryptName(String ciphertextName) throws AuthenticationFailedException;

}
