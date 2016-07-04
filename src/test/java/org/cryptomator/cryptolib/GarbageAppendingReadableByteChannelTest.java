/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

public class GarbageAppendingReadableByteChannelTest {

	private static final SecureRandom RANDOM_MOCK = new SecureRandom() {

		@Override
		public synchronized void nextBytes(byte[] bytes) {
			Arrays.fill(bytes, (byte) 0xFF);
		};

		@Override
		public int nextInt(int n) {
			return n;
		};
	};

	@Test
	public void testCrapAppending() throws IOException {
		byte[] buf = "hello world".getBytes(US_ASCII);
		ReadableByteChannel ch = Channels.newChannel(new ByteArrayInputStream(buf));
		GarbageAppendingReadableByteChannel appending = new GarbageAppendingReadableByteChannel(ch, RANDOM_MOCK);

		ByteBuffer buf1 = ByteBuffer.allocate(11);
		int first = appending.read(buf1);
		Assert.assertEquals(11, first);
		Assert.assertArrayEquals(buf, buf1.array());

		int second = appending.read(ByteBuffer.allocate(2 * 1024));
		Assert.assertEquals(2 * 1024, second);

		ByteBuffer buf3 = ByteBuffer.allocate(2 * 1024 + 1);
		int third = appending.read(buf3);
		Assert.assertEquals(2 * 1024, third);
		byte[] buf3Contents = new byte[2 * 1024];
		buf3.flip();
		buf3.get(buf3Contents);
		byte[] expected = new byte[2 * 1024];
		Arrays.fill(expected, (byte) 0xFF);
		Assert.assertArrayEquals(expected, buf3Contents);

		int fourth = appending.read(ByteBuffer.allocate(5));
		Assert.assertEquals(-1, fourth);

		Assert.assertTrue(appending.isOpen());
		appending.close();
		Assert.assertFalse(appending.isOpen());
	}

}
