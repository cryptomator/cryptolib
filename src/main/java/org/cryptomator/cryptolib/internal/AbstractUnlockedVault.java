package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.UnlockedVault;
import org.cryptomator.cryptolib.api.VaultFile;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

/**
 * Format-independent parts of an {@link UnlockedVault}: whole-file, stream and channel encryption on top of the format's header handling and layout.
 * <p>
 * Deliberately does not implement {@link UnlockedVault}: it is sealed to the two format interfaces in the Java 25 layer, so only the concrete vaults may be direct subtypes.
 */
public abstract class AbstractUnlockedVault {

	private final FileLayout layout;

	protected AbstractUnlockedVault(FileLayout layout) {
		this.layout = layout;
	}

	/**
	 * @return A file with a fresh header that has not been written yet
	 */
	protected abstract VaultFileImpl newFile();

	/**
	 * Parses an existing file's header.
	 *
	 * @param encryptedHeader The encrypted header, position to limit
	 * @param cleartextSize The file's cleartext size, {@code 0} if unknown
	 * @return The file
	 * @throws AuthenticationFailedException If the header is unauthentic
	 */
	protected abstract VaultFileImpl parseHeader(ByteBuffer encryptedHeader, long cleartextSize) throws AuthenticationFailedException;

	protected final FileLayout layout() {
		return layout;
	}

	/**
	 * Parses an encrypted header into a file, see {@link #parseHeader(ByteBuffer, long)}.
	 */
	protected interface HeaderParser {

		VaultFileImpl parse(ByteBuffer encryptedHeader, long cleartextSize) throws AuthenticationFailedException;

	}

	public VaultFile createFile() {
		return newFile();
	}

	public VaultFile openFile(ByteBuffer encryptedHeader, long ciphertextFileSize) throws AuthenticationFailedException {
		long cleartextSize = layout.cleartextSize(ciphertextFileSize);
		return parseHeader(encryptedHeader, cleartextSize);
	}

	public byte[] encryptFile(byte[] cleartext) {
		return encryptWith(newFile(), cleartext);
	}

	/**
	 * Encrypts a complete file with the given, not yet written file (e.g. one created with a node-type specific header).
	 *
	 * @param file The file whose header to use; closed afterwards
	 * @param cleartext The cleartext
	 * @return The complete ciphertext including the header
	 */
	protected final byte[] encryptWith(VaultFileImpl file, byte[] cleartext) {
		try (VaultFileImpl closeable = file) {
			ByteBuffer result = ByteBuffer.allocate((int) layout.ciphertextSize(cleartext.length));
			result.put(file.encryptedHeader());
			long chunkCount = layout.chunkCount(cleartext.length);
			for (long chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
				int offset = (int) layout.cleartextChunkOffset(chunkIndex);
				int length = layout.cleartextChunkLength(cleartext.length, chunkIndex);
				file.encryptChunk(ByteBuffer.wrap(cleartext, offset, length), result, chunkIndex);
			}
			assert !result.hasRemaining();
			return result.array();
		}
	}

	public byte[] decryptFile(byte[] ciphertext) throws AuthenticationFailedException {
		return decryptWith(this::parseHeader, ciphertext);
	}

	/**
	 * Decrypts a complete file, parsing its header with the given parser (e.g. one expecting a node-type specific header).
	 *
	 * @param parser Parses the header
	 * @param ciphertext The complete ciphertext including the header
	 * @return The cleartext
	 * @throws AuthenticationFailedException If the header or any chunk is unauthentic
	 */
	protected final byte[] decryptWith(HeaderParser parser, byte[] ciphertext) throws AuthenticationFailedException {
		if (ciphertext.length < layout.headerSize()) {
			throw new IllegalArgumentException("ciphertext shorter than header");
		}
		long cleartextSize = layout.cleartextSize(ciphertext.length);
		ByteBuffer header = ByteBuffer.wrap(ciphertext, 0, layout.headerSize());
		try (VaultFileImpl file = parser.parse(header, cleartextSize)) {
			ByteBuffer result = ByteBuffer.allocate((int) cleartextSize);
			long chunkCount = layout.chunkCount(cleartextSize);
			for (long chunkIndex = 0; chunkIndex < chunkCount; chunkIndex++) {
				int offset = (int) layout.ciphertextChunkOffset(chunkIndex);
				int length = layout.ciphertextChunkLength(cleartextSize, chunkIndex);
				file.decryptChunk(ByteBuffer.wrap(ciphertext, offset, length), result, chunkIndex);
			}
			assert !result.hasRemaining();
			return result.array();
		}
	}

	public WritableByteChannel encryptingChannel(WritableByteChannel ciphertextSink) {
		return new EncryptingWritableByteChannel(ciphertextSink, newFile(), layout);
	}

	public ReadableByteChannel decryptingChannel(ReadableByteChannel ciphertextSource) {
		return new DecryptingReadableByteChannel(ciphertextSource, header -> parseHeader(header, 0), layout);
	}

	public ReadableByteChannel encryptingChannel(ReadableByteChannel cleartextSource) {
		return new EncryptingReadableByteChannel(cleartextSource, newFile(), layout);
	}

	public OutputStream encryptingStream(OutputStream ciphertextSink) {
		return Channels.newOutputStream(encryptingChannel(Channels.newChannel(ciphertextSink)));
	}

	public InputStream decryptingStream(InputStream ciphertextSource) {
		return Channels.newInputStream(decryptingChannel(Channels.newChannel(ciphertextSource)));
	}

	public int headerSize() {
		return layout.headerSize();
	}

	public int cleartextChunkSize() {
		return layout.cleartextChunkSize();
	}

	public int ciphertextChunkSize() {
		return layout.ciphertextChunkSize();
	}

	public long ciphertextSize(long cleartextSize) {
		return layout.ciphertextSize(cleartextSize);
	}

	public long cleartextSize(long ciphertextFileSize) {
		return layout.cleartextSize(ciphertextFileSize);
	}

}
