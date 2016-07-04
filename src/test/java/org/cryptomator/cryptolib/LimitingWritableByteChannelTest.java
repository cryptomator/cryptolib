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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;

import org.junit.Assert;
import org.junit.Test;

public class LimitingWritableByteChannelTest {

	@Test
	public void testLimiting() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		WritableByteChannel ch = Channels.newChannel(baos);
		WritableByteChannel limited = new LimitingWritableByteChannel(ch, 7);

		int first = limited.write(US_ASCII.encode("hell"));
		Assert.assertEquals(4, first);
		Assert.assertArrayEquals("hell".getBytes(US_ASCII), baos.toByteArray());

		int second = limited.write(ByteBuffer.allocate(0));
		Assert.assertEquals(0, second);
		Assert.assertArrayEquals("hell".getBytes(US_ASCII), baos.toByteArray());

		int third = limited.write(US_ASCII.encode("o world"));
		Assert.assertEquals(3, third);
		Assert.assertArrayEquals("hello w".getBytes(US_ASCII), baos.toByteArray());

		int fourth = limited.write(ByteBuffer.allocate(10));
		Assert.assertEquals(0, fourth);
		Assert.assertArrayEquals("hello w".getBytes(US_ASCII), baos.toByteArray());

		Assert.assertTrue(limited.isOpen());
		limited.close();
		Assert.assertFalse(limited.isOpen());
	}

}
