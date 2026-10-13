package org.cryptomator.cryptolib.api;

import java.io.IOException;

/**
 * One entry within a {@link VaultDirectory}: the ciphertext name of a child and the layout of the well-known files below it.
 * <p>
 * Whether the entry is a file, a directory or a symbolic link is not known to cryptolib; the caller decides by checking which of {@link #dirFile()}, {@link #symlinkFile()} or
 * {@link #contentsFile()} exists. All paths returned by this interface are relative to the parent's {@link VaultDirectory#dirPath()} and use {@code /} as separator.
 */
public interface VaultNode {

	/**
	 * @return The name of the entry as stored on disk: the full ciphertext name, or its shortened form if it exceeds the vault's shortening threshold
	 */
	String name();

	/**
	 * @return {@code true} if {@link #name()} is a shortened name and the full ciphertext name must be stored in {@link #inflatedNameFile()}
	 */
	boolean isShortened();

	/**
	 * @return The full ciphertext name including its extension; equals {@link #name()} unless {@link #isShortened()}
	 */
	String inflated();

	/**
	 * @return Path of the file holding the entry's content if it is a regular file: {@link #name()} itself, or {@code <name>/contents.c9r} if shortened
	 */
	String contentsFile();

	/**
	 * @return Path of the directory file ({@code <name>/dir.c9r} or {@code <name>/dir.uvf}) if the entry is a directory
	 */
	String dirFile();

	/**
	 * @return Path of the symlink file ({@code <name>/symlink.c9r} or {@code <name>/symlink.uvf}) if the entry is a symbolic link
	 */
	String symlinkFile();

	/**
	 * @return Path of the file holding the inflated name ({@code <name>/name.c9s})
	 * @throws IllegalStateException If the name is not shortened
	 */
	String inflatedNameFile();

	/**
	 * Resolves the directory this entry points at by reading its {@link #dirFile()}.
	 *
	 * @param reader Reads files from the vault
	 * @return The directory
	 * @throws IOException If the reader fails (e.g. because the entry is not a directory)
	 * @throws AuthenticationFailedException If the directory file is unauthentic
	 */
	VaultDirectory directory(VaultReader reader) throws IOException, AuthenticationFailedException;

	/**
	 * Resolves the directory this entry points at from the contents of its {@link #dirFile()}.
	 *
	 * @param dirFileContents The contents of the directory file
	 * @return The directory
	 * @throws AuthenticationFailedException If the directory file is unauthentic
	 */
	VaultDirectory directory(byte[] dirFileContents) throws AuthenticationFailedException;

	/**
	 * Reads the target of the symbolic link this entry represents from its {@link #symlinkFile()}.
	 *
	 * @param reader Reads files from the vault
	 * @return The link target
	 * @throws IOException If the reader fails (e.g. because the entry is not a symbolic link)
	 * @throws AuthenticationFailedException If the symlink file is unauthentic
	 */
	String symlinkTarget(VaultReader reader) throws IOException, AuthenticationFailedException;

	/**
	 * Creates this entry as a directory pointing at {@code child}: writes the inflated name file if shortened, the directory file, and the child's metadata backup (which creates the
	 * child's content directory).
	 *
	 * @param child The directory to link, usually from {@link UnlockedVault#newDirectory()}
	 * @param writer Writes files into the vault
	 * @throws IOException If the writer fails
	 */
	void createDirectory(VaultDirectory child, VaultWriter writer) throws IOException;

	/**
	 * Creates this entry as a symbolic link: writes the inflated name file if shortened and the symlink file.
	 *
	 * @param target The link target
	 * @param writer Writes files into the vault
	 * @throws IOException If the writer fails
	 */
	void createSymlink(String target, VaultWriter writer) throws IOException;

}
