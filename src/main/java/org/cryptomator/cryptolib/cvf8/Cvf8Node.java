package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultNode;
import org.cryptomator.cryptolib.api.VaultReader;
import org.cryptomator.cryptolib.api.VaultWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * An entry within a {@link Cvf8Directory}, shortened if its ciphertext name exceeds the vault's shortening threshold.
 */
final class Cvf8Node implements VaultNode {

	private final Cvf8Directory parent;
	private final String inflated;
	private final String name;
	private final boolean shortened;

	Cvf8Node(Cvf8Directory parent, String ciphertextName) {
		this.parent = parent;
		this.inflated = ciphertextName;
		this.shortened = ciphertextName.length() > parent.vault().shorteningThreshold();
		this.name = shortened ? Cvf8Names.shorten(ciphertextName) : ciphertextName;
	}

	@Override
	public String name() {
		return name;
	}

	@Override
	public boolean isShortened() {
		return shortened;
	}

	@Override
	public String inflated() {
		return inflated;
	}

	@Override
	public String contentsFile() {
		return shortened ? name + "/" + Constants.CONTENTS_FILE_NAME : name;
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
		if (!shortened) {
			throw new IllegalStateException("Name is not shortened: " + name);
		}
		return name + "/" + Constants.INFLATED_NAME_FILE_NAME;
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
		writeInflatedNameIfShortened(writer);
		writer.write(relativeToVault(dirFile()), child.encryptedMetadata());
		child.writeMetadataBackup(writer);
	}

	@Override
	public void createSymlink(String target, VaultWriter writer) throws IOException {
		writeInflatedNameIfShortened(writer);
		writer.write(relativeToVault(symlinkFile()), parent.vault().encryptSymlinkTarget(target));
	}

	private void writeInflatedNameIfShortened(VaultWriter writer) throws IOException {
		if (shortened) {
			writer.write(relativeToVault(inflatedNameFile()), inflated.getBytes(StandardCharsets.UTF_8));
		}
	}

	private String relativeToVault(String pathRelativeToParent) {
		return parent.dirPath() + "/" + pathRelativeToParent;
	}

	@Override
	public String toString() {
		return "Cvf8Node[" + name + "]";
	}

}
