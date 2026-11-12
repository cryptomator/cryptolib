package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.api.VaultNode;

/**
 * A {@link VaultNode} stored under its full ciphertext name.
 */
public final class PlainVaultNode implements VaultNode {

	private final String name;
	private final String dirFile;
	private final String symlinkFile;

	/**
	 * @param name The full ciphertext name
	 * @param dirFileName Name of the format's directory file, e.g. {@code dir.uvf}
	 * @param symlinkFileName Name of the format's symlink file, e.g. {@code symlink.uvf}
	 */
	public PlainVaultNode(String name, String dirFileName, String symlinkFileName) {
		this.name = name;
		this.dirFile = name + "/" + dirFileName;
		this.symlinkFile = name + "/" + symlinkFileName;
	}

	@Override
	public String name() {
		return name;
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
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj instanceof PlainVaultNode) {
			PlainVaultNode other = (PlainVaultNode) obj;
			return name.equals(other.name) && dirFile.equals(other.dirFile) && symlinkFile.equals(other.symlinkFile);
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
		return "VaultNode[" + name + "]";
	}

}
