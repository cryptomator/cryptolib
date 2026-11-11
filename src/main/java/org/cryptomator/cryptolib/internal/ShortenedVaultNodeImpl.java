package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.api.ShortenedVaultNode;

import java.nio.charset.StandardCharsets;

/**
 * A {@link ShortenedVaultNode} whose layout is given by its format's name shortener.
 */
public final class ShortenedVaultNodeImpl implements ShortenedVaultNode {

	private final String name;
	private final String shortenedName;
	private final String contentsFile;
	private final String dirFile;
	private final String symlinkFile;
	private final String sidecarFile;

	/**
	 * @param name The full ciphertext name
	 * @param shortenedName The name the entry is stored under
	 * @param contentsFile Path of the file holding a regular file's contents
	 * @param dirFile Path of the directory file
	 * @param symlinkFile Path of the symlink file
	 * @param sidecarFile Path of the file holding the full name
	 */
	public ShortenedVaultNodeImpl(String name, String shortenedName, String contentsFile, String dirFile, String symlinkFile, String sidecarFile) {
		this.name = name;
		this.shortenedName = shortenedName;
		this.contentsFile = contentsFile;
		this.dirFile = dirFile;
		this.symlinkFile = symlinkFile;
		this.sidecarFile = sidecarFile;
	}

	@Override
	public String name() {
		return name;
	}

	@Override
	public String shortenedName() {
		return shortenedName;
	}

	@Override
	public String contentsFile() {
		return contentsFile;
	}

	@Override
	public String dirFile() {
		return dirFile;
	}

	@Override
	public String symlinkFile() {
		return symlinkFile;
	}

	@Override
	public String sidecarFile() {
		return sidecarFile;
	}

	@Override
	public byte[] sidecarContents() {
		return name.getBytes(StandardCharsets.UTF_8);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj instanceof ShortenedVaultNodeImpl) {
			ShortenedVaultNodeImpl other = (ShortenedVaultNodeImpl) obj;
			return name.equals(other.name) && shortenedName.equals(other.shortenedName) && sidecarFile.equals(other.sidecarFile);
		} else {
			return false;
		}
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public String toString() {
		return "ShortenedVaultNode[" + shortenedName + "]";
	}

}
