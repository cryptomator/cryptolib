package org.cryptomator.cryptolib.api;

/**
 * One entry within a {@link VaultDirectory}, identified by its full ciphertext name, plus the layout of the well-known files below it.
 * <p>
 * A node is a plain value without key material. Whether the entry is a file, a directory or a symbolic link is not known to cryptolib; the caller decides by checking which of
 * {@link #dirFile()} or {@link #symlinkFile()} exists. All paths returned by this interface are relative to the parent's {@link VaultDirectory#dirPath()} and use {@code /} as separator.
 * <p>
 * Nodes returned by {@link VaultDirectory#encryptName(String)} are never shortened: {@link #name()} is the entry as stored and, for a regular file, the file holding its contents. Where
 * long names need to be shortened, {@link NameShortener#shorten(String)} yields the {@link ShortenedVaultNode} to use instead.
 */
public interface VaultNode {

	/**
	 * @return The full ciphertext name of the entry including its extension ({@code *.c9r} / {@code *.uvf})
	 */
	String name();

	/**
	 * @return Path of the directory file ({@code dir.c9r} / {@code dir.uvf}) if the entry is a directory
	 */
	String dirFile();

	/**
	 * @return Path of the symlink file ({@code symlink.c9r} / {@code symlink.uvf}) if the entry is a symbolic link
	 */
	String symlinkFile();

}
