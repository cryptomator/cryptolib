/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import static org.cryptomator.cryptolib.Constants.PADDING_LOWER_BOUND;
import static org.cryptomator.cryptolib.Constants.PADDING_UPPER_BOUND;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.SecureRandom;

class GarbageAppendingReadableByteChannel extends CountingReadableByteChannel {

	private boolean eofReached = false;
	private final SecureRandom random;
	private final ByteBuffer garbage;
	private int toBeAppended = 0;

	public GarbageAppendingReadableByteChannel(ReadableByteChannel delegate, SecureRandom random) {
		super(delegate);
		this.random = random;
		byte[] garbagePattern = new byte[33];
		random.nextBytes(garbagePattern);
		byte[] garbage = new byte[32 * 1024];
		fillArray(garbage, garbagePattern);
		this.garbage = ByteBuffer.wrap(garbage);
	}

	private static void fillArray(byte[] array, byte[] pattern) {
		for (int i = 0; i < array.length; i += pattern.length) {
			System.arraycopy(pattern, 0, array, i, Math.min(pattern.length, array.length - i));
		}
	}

	@Override
	public int read(ByteBuffer dst) throws IOException {
		if (eofReached && toBeAppended == 0) {
			return -1;
		} else if (eofReached) {
			int totalAppended = 0;
			while (toBeAppended > 0 && dst.hasRemaining()) {
				int numBytes = Math.min(toBeAppended, garbage.capacity());
				garbage.clear().limit(numBytes);
				int appended = ByteBuffers.copy(garbage, dst);
				toBeAppended -= appended;
				totalAppended += appended;
			}
			return totalAppended;
		} else {
			return readFromDelegate(dst);
		}
	}

	private int readFromDelegate(ByteBuffer dst) throws IOException {
		int read = super.read(dst);
		if (read == -1) {
			eofReached = true;
			long actualSize = getNumberOfBytesRead();
			int maxPaddingLength = (int) Math.min(Math.max(actualSize / 10, PADDING_LOWER_BOUND), PADDING_UPPER_BOUND); // preferably 10%, but at least lower bound and no more than upper bound
			toBeAppended = random.nextInt(maxPaddingLength);
			return this.read(dst);
		} else {
			return read;
		}
	}

}
