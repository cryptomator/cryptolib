package org.cryptomator.cryptolib.v3;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.DirectoryMetadata;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.RevolvingMasterkey;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import static org.cryptomator.cryptolib.v3.Constants.UVF_FILE_EXT;

class DirectoryContentCryptorImpl implements DirectoryContentCryptor {

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
		byte[] dirId = masterkey.rootDirId();
		return new DirectoryMetadataImpl(masterkey.firstRevision(), dirId);
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
	public byte[] encryptDirectoryMetadata(DirectoryMetadata directoryMetadata) {
		DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.cast(directoryMetadata);
		ByteBuffer cleartextBuf = ByteBuffer.wrap(metadataImpl.dirId());
		FileHeader header = cryptor.fileHeaderCryptor(metadataImpl.seedId()).create();
		ByteBuffer headerBuf = cryptor.fileHeaderCryptor().encryptHeader(header);
		ByteBuffer contentBuf = cryptor.fileContentCryptor().encryptChunk(cleartextBuf, 0, header);
		byte[] result = new byte[headerBuf.remaining() + contentBuf.remaining()];
		headerBuf.get(result, 0, headerBuf.remaining());
		contentBuf.get(result, headerBuf.limit(), contentBuf.remaining());
		return result;
	}

	// DIR PATH

	@Override
	public String dirPath(DirectoryMetadata directoryMetadata) {
		DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.cast(directoryMetadata);
		FileNameCryptorImpl fileNameCryptor = cryptor.fileNameCryptor(metadataImpl.seedId());
		String dirIdStr = fileNameCryptor.hashDirectoryId(metadataImpl.dirId());
		assert dirIdStr.length() == 32;
		return "d/" + dirIdStr.substring(0, 2) + "/" + dirIdStr.substring(2);
	}

	// FILE NAMES

	@Override
	public Decrypting fileNameDecryptor(DirectoryMetadata directoryMetadata) {
		DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.cast(directoryMetadata);
		byte[] dirId = metadataImpl.dirId();
		FileNameCryptorImpl fileNameCryptor = cryptor.fileNameCryptor(metadataImpl.seedId());
		return ciphertextAndExt -> {
			String ciphertext = removeExtension(ciphertextAndExt);
			return fileNameCryptor.decryptFilename(BaseEncoding.base64Url(), ciphertext, dirId);
		};
	}

	@Override
	public Encrypting fileNameEncryptor(DirectoryMetadata directoryMetadata) {
		DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.cast(directoryMetadata);
		byte[] dirId = metadataImpl.dirId();
		FileNameCryptorImpl fileNameCryptor = cryptor.fileNameCryptor(metadataImpl.seedId());
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
