package org.cryptomator.cryptolib.uvf;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultNode;
import org.cryptomator.cryptolib.api.VaultReader;
import org.cryptomator.cryptolib.api.VaultWriter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

/**
 * A UVF directory, identified by its 32 byte directory id and the seed it was created with.
 */
final class UvfDirectory implements VaultDirectory {

	private final UvfVault vault;
	private final int seedId;
	private final byte[] dirId;
	private volatile String dirHash; // computed lazily

	UvfDirectory(UvfVault vault, int seedId, byte[] dirId) {
		if (dirId.length != Constants.DIR_ID_LEN) {
			throw new IllegalArgumentException("Invalid directory id length " + dirId.length);
		}
		this.vault = vault;
		this.seedId = seedId;
		this.dirId = dirId.clone();
	}

	UvfVault vault() {
		return vault;
	}

	int seedId() {
		return seedId;
	}

	byte[] rawDirId() {
		return dirId;
	}

	@Override
	public byte[] dirId() {
		return dirId.clone();
	}

	@Override
	public String dirHash() {
		String result = dirHash;
		if (result == null) {
			result = vault.names().hashDirectoryId(dirId, seedId);
			assert result.length() == 32;
			dirHash = result;
		}
		return result;
	}

	@Override
	public String dirPath() {
		String hash = dirHash();
		return Constants.DATA_DIR_NAME + "/" + hash.substring(0, 2) + "/" + hash.substring(2);
	}

	@Override
	public String backupFilePath() {
		return dirPath() + "/" + Constants.DIR_FILE_NAME;
	}

	@Override
	public byte[] encryptedMetadata() {
		return vault.encryptDirectoryMetadata(seedId, dirId);
	}

	@Override
	public byte[] encryptedMetadataBackup() {
		return vault.encryptDirectoryMetadata(seedId, dirId); // same format, independently encrypted
	}

	@Override
	public void writeMetadataBackup(VaultWriter writer) throws IOException {
		writer.write(backupFilePath(), encryptedMetadataBackup());
	}

	@Override
	public VaultNode encryptName(String cleartextName) {
		String ciphertextName = vault.names().encryptName(cleartextName, dirId, seedId) + Constants.FILE_EXT;
		return new UvfNode(this, ciphertextName);
	}

	@Override
	public String decryptName(String nameOnDisk, VaultReader reader) throws AuthenticationFailedException {
		return decryptName(nameOnDisk); // UVF has no name shortening
	}

	@Override
	public String decryptName(String ciphertextName) throws AuthenticationFailedException {
		if (!ciphertextName.endsWith(Constants.FILE_EXT)) {
			throw new IllegalArgumentException("Not a " + Constants.FILE_EXT + " name: " + ciphertextName);
		}
		String ciphertext = ciphertextName.substring(0, ciphertextName.length() - Constants.FILE_EXT.length());
		return vault.names().decryptName(ciphertext, dirId, seedId);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj instanceof UvfDirectory) {
			UvfDirectory other = (UvfDirectory) obj;
			return seedId == other.seedId && Arrays.equals(dirId, other.dirId);
		} else {
			return false;
		}
	}

	@Override
	public int hashCode() {
		return 31 * seedId + Arrays.hashCode(dirId);
	}

	@Override
	public String toString() {
		return "UvfDirectory[seed=" + seedId + ", dirId=" + Base64.getUrlEncoder().withoutPadding().encodeToString(dirId) + "]";
	}

}
