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

	public VaultFile createFile() {
		return newFile();
	}

	public VaultFile openFile(ByteBuffer encryptedHeader, long ciphertextFileSize) throws AuthenticationFailedException {
		long cleartextSize = layout.cleartextSize(ciphertextFileSize);
		return parseHeader(encryptedHeader, cleartextSize);
	}

	public byte[] encryptFile(byte[] cleartext) {
		try (VaultFileImpl file = newFile()) {
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
		if (ciphertext.length < layout.headerSize()) {
			throw new IllegalArgumentException("ciphertext shorter than header");
		}
		long cleartextSize = layout.cleartextSize(ciphertext.length);
		ByteBuffer header = ByteBuffer.wrap(ciphertext, 0, layout.headerSize());
		try (VaultFileImpl file = parseHeader(header, cleartextSize)) {
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
