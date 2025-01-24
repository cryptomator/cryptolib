package org.cryptomator.cryptolib.v3;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.RevolvingMasterkey;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import static org.cryptomator.cryptolib.v3.Constants.UVF_FILE_EXT;

class DirectoryContentCryptorImpl implements DirectoryContentCryptor<DirectoryMetadataImpl> {

	private final RevolvingMasterkey masterkey;
	private final SecureRandom random;
	private final CryptorImpl cryptor;

	public DirectoryContentCryptorImpl(RevolvingMasterkey masterkey, SecureRandom random, CryptorImpl cryptor) {
		this.masterkey = masterkey;
		this.random = random;
		this.cryptor = cryptor;
	}

	// DIRECTORY METADATA

	@Override
	public DirectoryMetadataImpl rootDirectoryMetadata() {
		// TODO
		return null;
	}

	@Override
	public DirectoryMetadataImpl newDirectoryMetadata() {
		byte[] dirId = new byte[32];
		random.nextBytes(dirId);
		return new DirectoryMetadataImpl(masterkey.currentRevision(), dirId);
	}

	@Override
	public DirectoryMetadataImpl decryptDirectoryMetadata(byte[] ciphertext) throws AuthenticationFailedException {
		if (ciphertext.length != 128) {
			throw new IllegalArgumentException("Invalid dir.uvf length: " + ciphertext.length);
		}
		int headerSize = cryptor.fileHeaderCryptor().headerSize();
		ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
		ByteBuffer headerBuf = buffer.duplicate();
		headerBuf.position(0).limit(headerSize);
		ByteBuffer contentBuf = buffer.duplicate();
		contentBuf.position(headerSize);
		FileHeaderImpl header = cryptor.fileHeaderCryptor().decryptHeader(headerBuf);
		ByteBuffer plaintext = cryptor.fileContentCryptor().decryptChunk(contentBuf, 0, header, true);
		assert plaintext.remaining() == 32;
		byte[] dirId = new byte[32];
		plaintext.get(dirId);
		return new DirectoryMetadataImpl(header.getSeedId(), dirId);
	}

	@Override
	public byte[] encryptDirectoryMetadata(DirectoryMetadataImpl directoryMetadata) {
		ByteBuffer cleartextBuf = ByteBuffer.wrap(directoryMetadata.dirId());
		FileHeader header = cryptor.fileHeaderCryptor().create();
		ByteBuffer headerBuf = cryptor.fileHeaderCryptor().encryptHeader(header);
		ByteBuffer contentBuf = cryptor.fileContentCryptor().encryptChunk(cleartextBuf, 0, header);
		byte[] result = new byte[headerBuf.remaining() + contentBuf.remaining()];
		headerBuf.get(result, 0, headerBuf.remaining());
		contentBuf.get(result, headerBuf.limit(), contentBuf.remaining());
		return result;
	}

	// FILE NAMES

	@Override
	public Decrypting fileNameDecryptor(DirectoryMetadataImpl directoryMetadata) {
		byte[] dirId = directoryMetadata.dirId();
		FileNameCryptorImpl fileNameCryptor = new FileNameCryptorImpl(masterkey, directoryMetadata.seedId());
		return ciphertextAndExt -> {
			String ciphertext = removeExtension(ciphertextAndExt);
			return fileNameCryptor.decryptFilename(BaseEncoding.base64Url(), ciphertext, dirId);
		};
	}

	@Override
	public Encrypting fileNameEncryptor(DirectoryMetadataImpl directoryMetadata) {
		byte[] dirId = directoryMetadata.dirId();
		FileNameCryptorImpl fileNameCryptor = new FileNameCryptorImpl(masterkey, directoryMetadata.seedId());
		return plaintext -> {
			String ciphertext = fileNameCryptor.encryptFilename(BaseEncoding.base64Url(), plaintext, dirId);
			return ciphertext + UVF_FILE_EXT;
		};
	}

	private static String removeExtension(String filename) {
		if (filename.endsWith(UVF_FILE_EXT)) {
			return filename.substring(0, filename.length() - UVF_FILE_EXT.length());
		} else {
			throw new IllegalArgumentException("Not a " + UVF_FILE_EXT + " file: " + filename);
		}
	}

}
