package org.cryptomator.cryptolib.v2;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.DirectoryMetadata;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.cryptomator.cryptolib.v2.Constants.C9R_FILE_EXT;

class DirectoryContentCryptorImpl implements DirectoryContentCryptor {

	private final CryptorImpl cryptor;

	public DirectoryContentCryptorImpl(CryptorImpl cryptor) {
		this.cryptor = cryptor;
	}

	// DIRECTORY METADATA

	@Override
	public DirectoryMetadataImpl rootDirectoryMetadata() {
		return new DirectoryMetadataImpl(new byte[0]);
	}

	@Override
	public DirectoryMetadataImpl newDirectoryMetadata() {
		byte[] dirId = UUID.randomUUID().toString().getBytes(StandardCharsets.US_ASCII);
		return new DirectoryMetadataImpl(dirId);
	}

	@Override
	public DirectoryMetadataImpl decryptDirectoryMetadata(byte[] ciphertext) {
		// dirId is stored in plaintext
		return new DirectoryMetadataImpl(ciphertext);
	}

	@Override
	public byte[] encryptDirectoryMetadata(DirectoryMetadata directoryMetadata) {
		// dirId is stored in plaintext
		DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.cast(directoryMetadata);
		return metadataImpl.dirId();
	}

	// DIR PATH

	@Override
	public String dirPath(DirectoryMetadata directoryMetadata) {
		DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.cast(directoryMetadata);
		String dirIdStr = cryptor.fileNameCryptor().hashDirectoryId(metadataImpl.dirId());
		assert dirIdStr.length() == 32;
		return "d/" + dirIdStr.substring(0, 2) + "/" + dirIdStr.substring(2);
	}

	// FILE NAMES

	@Override
	public Decrypting fileNameDecryptor(DirectoryMetadata directoryMetadata) {
		DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.cast(directoryMetadata);
		byte[] dirId = metadataImpl.dirId();
		FileNameCryptorImpl fileNameCryptor = cryptor.fileNameCryptor();
		return ciphertextAndExt -> {
			String ciphertext = removeExtension(ciphertextAndExt);
			return fileNameCryptor.decryptFilename(BaseEncoding.base64Url(), ciphertext, dirId);
		};
	}

	@Override
	public Encrypting fileNameEncryptor(DirectoryMetadata directoryMetadata) {
		DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.cast(directoryMetadata);
		byte[] dirId = metadataImpl.dirId();
		FileNameCryptorImpl fileNameCryptor = cryptor.fileNameCryptor();
		return plaintext -> {
			String ciphertext = fileNameCryptor.encryptFilename(BaseEncoding.base64Url(), plaintext, dirId);
			return ciphertext + C9R_FILE_EXT;
		};
	}

	private static String removeExtension(String filename) {
		if (filename.endsWith(C9R_FILE_EXT)) {
			return filename.substring(0, filename.length() - C9R_FILE_EXT.length());
		} else {
			throw new IllegalArgumentException("Not a " + C9R_FILE_EXT + " file: " + filename);
		}
	}
}
