package org.cryptomator.cryptolib;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;

/**
 * A ReadableByteChannel, that discards input after a given number of bytes.
 */
class LimitingWritableByteChannel implements WritableByteChannel {

	private final WritableByteChannel delegate;
	private final long limit;
	private long written;

	public LimitingWritableByteChannel(WritableByteChannel delegate, long limit) {
		this.delegate = delegate;
		this.limit = limit;
		this.written = 0;
	}

	@Override
	public int write(ByteBuffer src) throws IOException {
		if (written >= limit) {
			src.position(src.limit());
			return 0;
		} else {
			final int remaining = (int) Math.min(limit - written, src.remaining());
			ByteBuffer buf = src.asReadOnlyBuffer();
			buf.limit(buf.position() + remaining);
			int result = delegate.write(buf);
			written += result;
			return result;
		}
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
