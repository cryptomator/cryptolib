package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.common.ByteBuffers;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;

/**
 * Encrypts everything written to it chunk by chunk into a delegate channel, header first.
 */
final class EncryptingWritableByteChannel implements WritableByteChannel {

	private final WritableByteChannel delegate;
	private final VaultFileImpl file;
	private final FileLayout layout;
	private final ByteBuffer cleartextBuffer;
	private final ByteBuffer ciphertextBuffer;
	private boolean headerWritten = false;
	private long chunkIndex = 0;

	EncryptingWritableByteChannel(WritableByteChannel delegate, VaultFileImpl file, FileLayout layout) {
		this.delegate = delegate;
		this.file = file;
		this.layout = layout;
		this.cleartextBuffer = ByteBuffer.allocate(layout.cleartextChunkSize());
		this.ciphertextBuffer = ByteBuffer.allocate(layout.ciphertextChunkSize());
	}

	@Override
	public boolean isOpen() {
		return delegate.isOpen();
	}

	@Override
	public synchronized int write(ByteBuffer src) throws IOException {
		writeHeaderOnFirstWrite();
		int result = 0;
		while (src.hasRemaining()) {
			result += ByteBuffers.copy(src, cleartextBuffer);
			if (!cleartextBuffer.hasRemaining()) {
				encryptAndFlushBuffer();
			}
		}
		return result;
	}

	@Override
	public synchronized void close() throws IOException {
		try {
			writeHeaderOnFirstWrite();
			if (cleartextBuffer.position() > 0 || layout.hasEofChunk()) { // an empty final chunk is the EOF chunk, only formats that require it get one
				encryptAndFlushBuffer();
			}
			delegate.close();
		} finally {
			file.destroy();
		}
	}

	private void writeHeaderOnFirstWrite() throws IOException {
		if (!headerWritten) {
			writeFully(file.encryptedHeader());
			headerWritten = true;
		}
	}

	private void encryptAndFlushBuffer() throws IOException {
		cleartextBuffer.flip();
		ciphertextBuffer.clear();
		file.encryptChunk(cleartextBuffer, ciphertextBuffer, chunkIndex++);
		ciphertextBuffer.flip();
		writeFully(ciphertextBuffer);
		cleartextBuffer.clear();
	}

	private void writeFully(ByteBuffer buf) throws IOException {
		while (buf.hasRemaining()) {
			delegate.write(buf);
		}
	}

}
