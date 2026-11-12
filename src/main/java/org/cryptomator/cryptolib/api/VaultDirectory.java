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
	 * Encrypts the name of a child of this directory. The result is deterministic and never shortened, see {@link NameShortener}.
	 *
	 * @param cleartextName The child's cleartext name
	 * @return The child's node: its full ciphertext name and the layout of its well-known files
	 */
	VaultNode encryptName(String cleartextName);

	/**
	 * Decrypts the full ciphertext name of a child of this directory.
	 *
	 * @param ciphertextName The child's full ciphertext name including the extension ({@code *.c9r} / {@code *.uvf}); for shortened entries the result of {@link NameShortener#unshorten(String, byte[])}
	 * @return The child's cleartext name
	 * @throws AuthenticationFailedException If the name is unauthentic or does not belong to this directory
	 * @throws IllegalArgumentException If {@code ciphertextName} is not a ciphertext node name (e.g. {@code dirid.c9r} or a shortened name)
	 */
	String decryptName(String ciphertextName) throws AuthenticationFailedException;

	/**
	 * Resolves the directory a child entry points at by reading its {@link VaultNode#dirFile()}.
	 *
	 * @param node A child of this directory, plain or {@link ShortenedVaultNode shortened}
	 * @param reader Reads files from the vault
	 * @return The directory
	 * @throws IOException If the reader fails (e.g. because the entry is not a directory)
	 * @throws AuthenticationFailedException If the directory file is unauthentic
	 */
	VaultDirectory directory(VaultNode node, VaultReader reader) throws IOException, AuthenticationFailedException;

	/**
	 * Reads the target of the symbolic link a child entry represents from its {@link VaultNode#symlinkFile()}.
	 *
	 * @param node A child of this directory, plain or {@link ShortenedVaultNode shortened}
	 * @param reader Reads files from the vault
	 * @return The link target
	 * @throws IOException If the reader fails (e.g. because the entry is not a symbolic link)
	 * @throws AuthenticationFailedException If the symlink file is unauthentic
	 */
	String symlinkTarget(VaultNode node, VaultReader reader) throws IOException, AuthenticationFailedException;

	/**
	 * Creates a child entry as a directory pointing at {@code child}: writes the directory file and the child's metadata backup (which creates the child's content directory).
	 * <p>
	 * The sidecar of a {@link ShortenedVaultNode} is not written by this method.
	 *
	 * @param node A child of this directory, plain or {@link ShortenedVaultNode shortened}
	 * @param child The directory to link, usually from {@link UnlockedVault#newDirectory()}
	 * @param writer Writes files into the vault
	 * @throws IOException If the writer fails
	 */
	void createDirectory(VaultNode node, VaultDirectory child, VaultWriter writer) throws IOException;

	/**
	 * Creates a child entry as a symbolic link by writing its symlink file.
	 * <p>
	 * The sidecar of a {@link ShortenedVaultNode} is not written by this method.
	 *
	 * @param node A child of this directory, plain or {@link ShortenedVaultNode shortened}
	 * @param target The link target
	 * @param writer Writes files into the vault
	 * @throws IOException If the writer fails
	 */
	void createSymlink(VaultNode node, String target, VaultWriter writer) throws IOException;

}
