package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

public class EncryptingReadableByteChannel implements ReadableByteChannel {

	private final ReadableByteChannel delegate;
	private final Cryptor cryptor;
	private final FileHeader header;

	private ByteBuffer ciphertextBuffer;
	private long chunk = 0;
	private boolean reachedEof;

	/**
	 * Creates an EncryptingReadableByteChannel that encrypts a whole cleartext file beginning at its first byte.
	 *
	 * @param src          A cleartext channel positioned at its begin
	 * @param cryptor      The cryptor to use
	 */
	public EncryptingReadableByteChannel(ReadableByteChannel src, Cryptor cryptor) {
		this.delegate = src;
		this.cryptor = cryptor;
		this.header = cryptor.fileHeaderCryptor().create();
		this.ciphertextBuffer = cryptor.fileHeaderCryptor().encryptHeader(header);
	}

	@Override
	public boolean isOpen() {
		return delegate.isOpen();
	}

	@Override
	public void close() throws IOException {
		delegate.close();
	}

	@Override
	public synchronized int read(ByteBuffer dst) throws IOException {
		if (reachedEof) {
			return -1;
		} else {
			return readInternal(dst);
		}
	}

	private int readInternal(ByteBuffer dst) throws IOException {
		int result = 0;
		while (dst.hasRemaining() && !reachedEof) {
			if (ciphertextBuffer.hasRemaining() || loadNextCiphertextChunk()) {
				result += ByteBuffers.copy(ciphertextBuffer, dst);
			} else {
				assert reachedEof : "no further ciphertext available";
			}
		}
		return result;
	}

	private boolean loadNextCiphertextChunk() throws IOException {
		ByteBuffer cleartextChunk = ByteBuffer.allocate(cryptor.fileContentCryptor().cleartextChunkSize());
		int read = ByteBuffers.fill(delegate, cleartextChunk);
		if (read == 0) {
			reachedEof = true;
			return false;
		} else {
			cleartextChunk.flip();
			ciphertextBuffer = cryptor.fileContentCryptor().encryptChunk(cleartextChunk, chunk++, header);
			return true;
		}
	}

}
