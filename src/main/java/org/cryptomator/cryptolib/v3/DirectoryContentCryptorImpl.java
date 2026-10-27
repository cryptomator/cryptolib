package org.cryptomator.cryptolib.v3;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.DirectoryMetadata;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.RevolvingMasterkey;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.text.Normalizer;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptolib.v3.Constants.UVF_FILE_EXT;

class DirectoryContentCryptorImpl implements DirectoryContentCryptor {

	private static final BaseEncoding BASE64URL = BaseEncoding.base64Url().omitPadding();

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
		byte[] dirId = new byte[Constants.DIR_ID_LEN];
		random.nextBytes(dirId);
		return new DirectoryMetadataImpl(masterkey.currentRevision(), dirId);
	}

	@Override
	public DirectoryMetadataImpl decryptDirectoryMetadata(byte[] ciphertext) throws AuthenticationFailedException {
		int expectedSize = cryptor.fileHeaderCryptor().headerSize() + (int) cryptor.fileContentCryptor().ciphertextSize(Constants.DIR_ID_LEN);
		if (ciphertext.length != expectedSize) {
			throw new IllegalArgumentException("Invalid dir.uvf length: " + ciphertext.length);
		}
		ByteBuffer plaintext = decryptSingleChunkFile(ciphertext, Constants.KDF_CONTEXT_DIR_HEADER);
		if (plaintext.remaining() != Constants.DIR_ID_LEN) {
			throw new IllegalArgumentException("Invalid dir.uvf cleartext length: " + plaintext.remaining());
		}
		byte[] dirId = new byte[Constants.DIR_ID_LEN];
		plaintext.get(dirId);
		int seedId = ByteBuffer.wrap(ciphertext, Constants.UVF_MAGIC_BYTES.length, Integer.BYTES).getInt(); // authenticated as part of the header
		return new DirectoryMetadataImpl(seedId, dirId);
	}

	@Override
	public byte[] encryptDirectoryMetadata(DirectoryMetadata directoryMetadata) {
		DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.cast(directoryMetadata);
		return encryptSingleChunkFile(ByteBuffer.wrap(metadataImpl.dirId()), metadataImpl.seedId(), Constants.KDF_CONTEXT_DIR_HEADER);
	}

	// SYMLINKS

	@Override
	public byte[] encryptSymlinkTarget(String target) {
		byte[] cleartext = Normalizer.normalize(target, Normalizer.Form.NFC).getBytes(UTF_8);
		if (cleartext.length > Constants.PAYLOAD_SIZE) {
			throw new IllegalArgumentException("Symlink target too long: " + cleartext.length + " bytes");
		}
		return encryptSingleChunkFile(ByteBuffer.wrap(cleartext), masterkey.currentRevision(), Constants.KDF_CONTEXT_SYMLINK_HEADER);
	}

	@Override
	public String decryptSymlinkTarget(byte[] ciphertext) throws AuthenticationFailedException {
		int headerSize = cryptor.fileHeaderCryptor().headerSize();
		if (ciphertext.length < headerSize || ciphertext.length > headerSize + Constants.CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid symlink.uvf length: " + ciphertext.length);
		}
		ByteBuffer plaintext = decryptSingleChunkFile(ciphertext, Constants.KDF_CONTEXT_SYMLINK_HEADER);
		return UTF_8.decode(plaintext).toString();
	}

	// encrypts a small cleartext as header + exactly one chunk (chunk number 0) under the given node type's header context
	private byte[] encryptSingleChunkFile(ByteBuffer cleartext, int seedId, byte[] headerContext) {
		FileHeaderCryptorImpl headerCryptor = cryptor.fileHeaderCryptor(seedId, headerContext);
		FileHeader header = headerCryptor.create();
		ByteBuffer headerBuf = headerCryptor.encryptHeader(header);
		ByteBuffer contentBuf = cryptor.fileContentCryptor().encryptChunk(cleartext, 0, header);
		byte[] result = new byte[headerBuf.remaining() + contentBuf.remaining()];
		headerBuf.get(result, 0, headerBuf.remaining());
		contentBuf.get(result, headerBuf.limit(), contentBuf.remaining());
		return result;
	}

	// decrypts a header + single chunk file under the given node type's header context; the chunk must be the only one, so there is no EOF chunk
	private ByteBuffer decryptSingleChunkFile(byte[] ciphertext, byte[] headerContext) throws AuthenticationFailedException {
		int headerSize = cryptor.fileHeaderCryptor().headerSize();
		ByteBuffer buffer = ByteBuffer.wrap(ciphertext);
		ByteBuffer headerBuf = buffer.duplicate();
		headerBuf.position(0).limit(headerSize);
		ByteBuffer contentBuf = buffer.duplicate();
		contentBuf.position(headerSize);
		// the seed of a new header does not matter for decryption, the context does:
		FileHeaderImpl header = cryptor.fileHeaderCryptor(masterkey.currentRevision(), headerContext).decryptHeader(headerBuf);
		return cryptor.fileContentCryptor().decryptChunk(contentBuf, 0, header, true);
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
			requireCanonicalBase64Url(ciphertext);
			String cleartext = fileNameCryptor.decryptFilename(BASE64URL, ciphertext, dirId);
			requireValidCleartextName(cleartext);
			return cleartext;
		};
	}

	@Override
	public Encrypting fileNameEncryptor(DirectoryMetadata directoryMetadata) {
		DirectoryMetadataImpl metadataImpl = DirectoryMetadataImpl.cast(directoryMetadata);
		byte[] dirId = metadataImpl.dirId();
		FileNameCryptorImpl fileNameCryptor = cryptor.fileNameCryptor(metadataImpl.seedId());
		return plaintext -> {
			String ciphertext = fileNameCryptor.encryptFilename(BASE64URL, plaintext, dirId);
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

	// the spec requires canonical decoding: no padding, no foreign characters, no non-zero trailing bits, so that each ciphertext has exactly one name
	private static void requireCanonicalBase64Url(String ciphertext) throws AuthenticationFailedException {
		try {
			if (!BASE64URL.encode(BASE64URL.decode(ciphertext)).equals(ciphertext)) {
				throw new AuthenticationFailedException("Non-canonical base64url ciphertext: " + ciphertext);
			}
		} catch (IllegalArgumentException e) {
			throw new AuthenticationFailedException("Invalid base64url ciphertext: " + ciphertext, e);
		}
	}

	// decrypted names are untrusted input (see "Decrypted Names" in the UVF implementation notes); file system specific rules remain the caller's job
	private static void requireValidCleartextName(String name) throws AuthenticationFailedException {
		if (name.isEmpty() || name.equals(".") || name.equals("..") || name.indexOf('/') != -1 || name.indexOf('\0') != -1) {
			throw new AuthenticationFailedException("Invalid cleartext name");
		}
	}

}
