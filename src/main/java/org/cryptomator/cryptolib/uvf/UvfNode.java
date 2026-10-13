package org.cryptomator.cryptolib.uvf;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultNode;
import org.cryptomator.cryptolib.api.VaultReader;
import org.cryptomator.cryptolib.api.VaultWriter;

import java.io.IOException;

/**
 * An entry within a {@link UvfDirectory}. UVF has no name shortening, so the name on disk is always the full ciphertext name.
 */
final class UvfNode implements VaultNode {

	private final UvfDirectory parent;
	private final String name;

	UvfNode(UvfDirectory parent, String ciphertextName) {
		this.parent = parent;
		this.name = ciphertextName;
	}

	@Override
	public String name() {
		return name;
	}

	@Override
	public boolean isShortened() {
		return false;
	}

	@Override
	public String inflated() {
		return name;
	}

	@Override
	public String contentsFile() {
		return name;
	}

	@Override
	public String dirFile() {
		return name + "/" + Constants.DIR_FILE_NAME;
	}

	@Override
	public String symlinkFile() {
		return name + "/" + Constants.SYMLINK_FILE_NAME;
	}

	@Override
	public String inflatedNameFile() {
		throw new IllegalStateException("UVF names are never shortened");
	}

	@Override
	public VaultDirectory directory(VaultReader reader) throws IOException, AuthenticationFailedException {
		return directory(reader.read(relativeToVault(dirFile())));
	}

	@Override
	public VaultDirectory directory(byte[] dirFileContents) throws AuthenticationFailedException {
		return parent.vault().directory(dirFileContents);
	}

	@Override
	public String symlinkTarget(VaultReader reader) throws IOException, AuthenticationFailedException {
		return parent.vault().decryptSymlinkTarget(reader.read(relativeToVault(symlinkFile())));
	}

	@Override
	public void createDirectory(VaultDirectory child, VaultWriter writer) throws IOException {
		writer.write(relativeToVault(dirFile()), child.encryptedMetadata());
		child.writeMetadataBackup(writer);
	}

	@Override
	public void createSymlink(String target, VaultWriter writer) throws IOException {
		writer.write(relativeToVault(symlinkFile()), parent.vault().encryptSymlinkTarget(target));
	}

	private String relativeToVault(String pathRelativeToParent) {
		return parent.dirPath() + "/" + pathRelativeToParent;
	}

	@Override
	public String toString() {
		return "UvfNode[" + name + "]";
	}

}
