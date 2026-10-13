package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.common.ByteBuffers;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.util.function.Function;

/**
 * Decrypts a complete ciphertext file (header first) read from a delegate channel.
 */
final class DecryptingReadableByteChannel implements ReadableByteChannel {

	private final ReadableByteChannel delegate;
	private final Function<ByteBuffer, VaultFileImpl> headerParser;
	private final FileLayout layout;
	private final ByteBuffer cleartextBuffer;
	private final ByteBuffer ciphertextBuffer;
	private VaultFileImpl file;
	private long chunkIndex = 0;
	private boolean lastChunkWasFull = true; // an empty file must still have its EOF chunk
	private boolean sawEmptyChunk = false;
	private boolean reachedEof = false;

	/**
	 * @param delegate Ciphertext source, positioned at the beginning of the header
	 * @param headerParser Turns the encrypted header into a file
	 * @param layout The format's layout
	 */
	DecryptingReadableByteChannel(ReadableByteChannel delegate, Function<ByteBuffer, VaultFileImpl> headerParser, FileLayout layout) {
		this.delegate = delegate;
		this.headerParser = headerParser;
		this.layout = layout;
		this.cleartextBuffer = ByteBuffer.allocate(layout.cleartextChunkSize());
		this.ciphertextBuffer = ByteBuffer.allocate(layout.ciphertextChunkSize());
		this.cleartextBuffer.limit(0); // empty until the first chunk is loaded
	}

	@Override
	public boolean isOpen() {
		return delegate.isOpen();
	}

	@Override
	public void close() throws IOException {
		try {
			delegate.close();
		} finally {
			if (file != null) {
				file.destroy();
			}
		}
	}

	@Override
	public synchronized int read(ByteBuffer dst) throws IOException, AuthenticationFailedException {
		loadHeaderIfNecessary();
		if (reachedEof) {
			return -1;
		}
		int result = 0;
		while (dst.hasRemaining() && !reachedEof) {
			if (cleartextBuffer.hasRemaining() || loadNextCleartextChunk()) {
				result += ByteBuffers.copy(cleartextBuffer, dst);
			}
		}
		if (result == 0 && reachedEof && dst.hasRemaining()) {
			return -1; // e.g. an empty file whose only chunk is the EOF chunk
		}
		return result;
	}

	private void loadHeaderIfNecessary() throws IOException, AuthenticationFailedException {
		if (file == null) {
			ByteBuffer headerBuf = ByteBuffer.allocate(layout.headerSize());
			int read = ByteBuffers.fill(delegate, headerBuf);
			if (read != headerBuf.capacity()) {
				throw new EOFException("Unable to read header from channel.");
			}
			headerBuf.flip();
			file = headerParser.apply(headerBuf);
		}
	}

	private boolean loadNextCleartextChunk() throws IOException, AuthenticationFailedException {
		ciphertextBuffer.clear();
		int read = ByteBuffers.fill(delegate, ciphertextBuffer);
		if (read == 0) {
			if (layout.hasEofChunk() && lastChunkWasFull) {
				throw new EOFException("Missing EOF chunk, ciphertext is truncated.");
			}
			reachedEof = true;
			return false;
		}
		if (read < layout.chunkOverhead()) {
			throw new EOFException("Truncated chunk, ciphertext is corrupt.");
		}
		if (sawEmptyChunk) {
			throw new IOException("Empty chunk in the middle of the file, ciphertext is corrupt.");
		}
		ciphertextBuffer.flip();
		cleartextBuffer.clear();
		file.decryptChunk(ciphertextBuffer, cleartextBuffer, chunkIndex++);
		cleartextBuffer.flip();
		lastChunkWasFull = cleartextBuffer.remaining() == layout.cleartextChunkSize();
		sawEmptyChunk = !cleartextBuffer.hasRemaining();
		return true;
	}

}
