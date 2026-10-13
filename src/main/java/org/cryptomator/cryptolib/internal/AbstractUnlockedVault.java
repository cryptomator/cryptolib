package org.cryptomator.cryptolib.internal;

import com.google.common.base.Preconditions;
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
 */
public abstract class AbstractUnlockedVault implements UnlockedVault {

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

	@Override
	public VaultFile createFile() {
		return newFile();
	}

	@Override
	public VaultFile openFile(ByteBuffer encryptedHeader, long ciphertextFileSize) throws AuthenticationFailedException {
		long cleartextSize = layout.cleartextSize(ciphertextFileSize);
		return parseHeader(encryptedHeader, cleartextSize);
	}

	@Override
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

	@Override
	public byte[] decryptFile(byte[] ciphertext) throws AuthenticationFailedException {
		Preconditions.checkArgument(ciphertext.length >= layout.headerSize(), "ciphertext shorter than header");
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

	@Override
	public WritableByteChannel encryptingChannel(WritableByteChannel ciphertextSink) {
		return new EncryptingWritableByteChannel(ciphertextSink, newFile(), layout);
	}

	@Override
	public ReadableByteChannel decryptingChannel(ReadableByteChannel ciphertextSource) {
		return new DecryptingReadableByteChannel(ciphertextSource, header -> parseHeader(header, 0), layout);
	}

	@Override
	public ReadableByteChannel encryptingChannel(ReadableByteChannel cleartextSource) {
		return new EncryptingReadableByteChannel(cleartextSource, newFile(), layout);
	}

	@Override
	public OutputStream encryptingStream(OutputStream ciphertextSink) {
		return Channels.newOutputStream(encryptingChannel(Channels.newChannel(ciphertextSink)));
	}

	@Override
	public InputStream decryptingStream(InputStream ciphertextSource) {
		return Channels.newInputStream(decryptingChannel(Channels.newChannel(ciphertextSource)));
	}

	@Override
	public int headerSize() {
		return layout.headerSize();
	}

	@Override
	public int cleartextChunkSize() {
		return layout.cleartextChunkSize();
	}

	@Override
	public int ciphertextChunkSize() {
		return layout.ciphertextChunkSize();
	}

	@Override
	public long ciphertextSize(long cleartextSize) {
		return layout.ciphertextSize(cleartextSize);
	}

	@Override
	public long cleartextSize(long ciphertextFileSize) {
		return layout.cleartextSize(ciphertextFileSize);
	}

}
