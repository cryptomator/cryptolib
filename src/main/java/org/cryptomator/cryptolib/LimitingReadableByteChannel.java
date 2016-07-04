/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

/**
 * A ReadableByteChannel, that reaches EOF after a given number of bytes (or at the real EOF).
 */
class LimitingReadableByteChannel implements ReadableByteChannel {

	private final ReadableByteChannel delegate;
	private final long limit;
	private long read;

	public LimitingReadableByteChannel(ReadableByteChannel delegate, long limit) {
		this.delegate = delegate;
		this.limit = limit;
		this.read = 0;
	}

	@Override
	public int read(ByteBuffer dst) throws IOException {
		if (read >= limit) {
			return -1;
		} else {
			final int origLimit = dst.limit();
			final int remaining = (int) Math.min(limit - read, dst.remaining());
			dst.limit(dst.position() + remaining);
			final int result = delegate.read(dst);
			read += result;
			dst.limit(origLimit);
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
