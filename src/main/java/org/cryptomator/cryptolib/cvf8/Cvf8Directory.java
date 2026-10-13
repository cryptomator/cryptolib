package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.VaultDirectory;
import org.cryptomator.cryptolib.api.VaultNode;
import org.cryptomator.cryptolib.api.VaultReader;
import org.cryptomator.cryptolib.api.VaultWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * A CVF8 directory, identified by its directory id (a UUID string, or the empty string for the root).
 */
final class Cvf8Directory implements VaultDirectory {

	private final Cvf8Vault vault;
	private final String dirId;
	private volatile String dirHash; // computed lazily

	Cvf8Directory(Cvf8Vault vault, String dirId) {
		this.vault = vault;
		this.dirId = dirId;
	}

	Cvf8Vault vault() {
		return vault;
	}

	String dirIdString() {
		return dirId;
	}

	@Override
	public byte[] dirId() {
		return dirId.getBytes(StandardCharsets.UTF_8);
	}

	@Override
	public String dirHash() {
		String result = dirHash;
		if (result == null) {
			result = vault.names().hashDirectoryId(dirId);
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
		return dirPath() + "/" + Constants.DIR_ID_BACKUP_FILE_NAME;
	}

	@Override
	public byte[] encryptedMetadata() {
		return dirId(); // dir.c9r stores the directory id in plaintext
	}

	@Override
	public byte[] encryptedMetadataBackup() {
		return vault.encryptFile(dirId());
	}

	@Override
	public void writeMetadataBackup(VaultWriter writer) throws IOException {
		writer.write(backupFilePath(), encryptedMetadataBackup());
	}

	@Override
	public VaultNode encryptName(String cleartextName) {
		String ciphertextName = vault.names().encryptName(cleartextName, dirId) + Constants.FILE_EXT;
		return new Cvf8Node(this, ciphertextName);
	}

	@Override
	public String decryptName(String nameOnDisk, VaultReader reader) throws IOException, AuthenticationFailedException {
		if (nameOnDisk.endsWith(Constants.SHORTENED_FILE_EXT)) {
			byte[] inflated = reader.read(dirPath() + "/" + nameOnDisk + "/" + Constants.INFLATED_NAME_FILE_NAME);
			return decryptName(new String(inflated, StandardCharsets.UTF_8));
		} else {
			return decryptName(nameOnDisk);
		}
	}

	@Override
	public String decryptName(String ciphertextName) throws AuthenticationFailedException {
		if (!ciphertextName.endsWith(Constants.FILE_EXT)) {
			throw new IllegalArgumentException("Not a " + Constants.FILE_EXT + " name: " + ciphertextName);
		}
		String ciphertext = ciphertextName.substring(0, ciphertextName.length() - Constants.FILE_EXT.length());
		return vault.names().decryptName(ciphertext, dirId);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj instanceof Cvf8Directory) {
			Cvf8Directory other = (Cvf8Directory) obj;
			return vault == other.vault && dirId.equals(other.dirId);
		} else {
			return false;
		}
	}

	@Override
	public int hashCode() {
		return dirId.hashCode();
	}

	@Override
	public String toString() {
		return "Cvf8Directory[" + dirId + "]";
	}

}
