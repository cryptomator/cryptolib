package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.common.ByteBuffers;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

/**
 * Pull-style counterpart of {@link EncryptingWritableByteChannel}: reading from it yields the encrypted form of a cleartext channel, header first.
 */
final class EncryptingReadableByteChannel implements ReadableByteChannel {

	private final ReadableByteChannel delegate;
	private final VaultFileImpl file;
	private final FileLayout layout;
	private final ByteBuffer cleartextBuffer;
	private final ByteBuffer ciphertextBuffer;
	private ByteBuffer pending; // bytes not yet handed out: the header first, then one ciphertext chunk at a time
	private long chunkIndex = 0;
	private boolean lastChunkWasFull = true; // so that an empty file still gets its EOF chunk
	private boolean eofChunkWritten = false;
	private boolean reachedEof = false;

	EncryptingReadableByteChannel(ReadableByteChannel delegate, VaultFileImpl file, FileLayout layout) {
		this.delegate = delegate;
		this.file = file;
		this.layout = layout;
		this.cleartextBuffer = ByteBuffer.allocate(layout.cleartextChunkSize());
		this.ciphertextBuffer = ByteBuffer.allocate(layout.ciphertextChunkSize());
		this.pending = file.encryptedHeader();
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
			file.destroy();
		}
	}

	@Override
	public synchronized int read(ByteBuffer dst) throws IOException {
		if (reachedEof) {
			return -1;
		}
		int result = 0;
		while (dst.hasRemaining() && !reachedEof) {
			if (pending.hasRemaining() || loadNextCiphertextChunk()) {
				result += ByteBuffers.copy(pending, dst);
			}
		}
		return result;
	}

	private boolean loadNextCiphertextChunk() throws IOException {
		cleartextBuffer.clear();
		int read = ByteBuffers.fill(delegate, cleartextBuffer);
		if (read == 0) {
			if (layout.hasEofChunk() && lastChunkWasFull && !eofChunkWritten) {
				eofChunkWritten = true;
				cleartextBuffer.limit(0);
				encryptChunk();
				return true;
			}
			reachedEof = true;
			return false;
		} else {
			cleartextBuffer.flip();
			lastChunkWasFull = cleartextBuffer.remaining() == layout.cleartextChunkSize();
			encryptChunk();
			return true;
		}
	}

	private void encryptChunk() {
		ciphertextBuffer.clear();
		file.encryptChunk(cleartextBuffer, ciphertextBuffer, chunkIndex++);
		ciphertextBuffer.flip();
		pending = ciphertextBuffer;
	}

}
