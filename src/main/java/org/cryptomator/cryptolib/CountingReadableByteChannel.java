package org.cryptomator.cryptolib;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

/**
 * A ReadableByteChannel, that counts, how many bytes have been read.
 */
class CountingReadableByteChannel implements ReadableByteChannel {

	private final ReadableByteChannel delegate;
	private long read;

	public CountingReadableByteChannel(ReadableByteChannel delegate) {
		this.delegate = delegate;
		this.read = 0;
	}

	@Override
	public int read(ByteBuffer dst) throws IOException {
		int result = delegate.read(dst);
		if (result > 0) {
			read += result;
		}
		return result;
	}

	public long getNumberOfBytesRead() {
		return read;
	}

	@Override
	public boolean isOpen() {
		return delegate.isOpen();
	}

	@Override
	public void close() throws IOException {
		delegate.close();
	}

}
