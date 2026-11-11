package org.cryptomator.cryptolib.api;

/**
 * A {@link VaultNode} whose name exceeds the shortening threshold and which is therefore stored under a short name, with a sidecar file holding the full name.
 * <p>
 * {@link #name()} remains the full ciphertext name, while {@link #dirFile()} and {@link #symlinkFile()} point below {@link #shortenedName()}.
 *
 * @see NameShortener#shorten(String)
 */
public interface ShortenedVaultNode extends VaultNode {

	/**
	 * @return The name of the entry as stored: {@code <hash>.c9s} / {@code <hash>.shortened.uvf}
	 */
	String shortenedName();

	/**
	 * @return Path of the file holding the entry's contents if it is a regular file: {@code <hash>.c9s/contents.c9r}, or {@link #shortenedName()} itself for UVF
	 */
	String contentsFile();

	/**
	 * @return Path of the file holding the full name: {@code <hash>.c9s/name.c9s} inside the entry, or {@code <hash>.original.uvf} next to it
	 */
	String sidecarFile();

	/**
	 * @return The contents of {@link #sidecarFile()}: the UTF-8 encoded {@link #name()}
	 */
	byte[] sidecarContents();

}
