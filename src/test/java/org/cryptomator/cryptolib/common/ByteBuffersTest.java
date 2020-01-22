/*******************************************************************************
 * Copyright (c) 2015, 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

public class ByteBuffersTest {

	@Test
	public void testCopyOfEmptySource() {
		final ByteBuffer src = ByteBuffer.allocate(0);
		final ByteBuffer dst = ByteBuffer.allocate(5);
		dst.put(new byte[3]);
		Assertions.assertEquals(0, src.position());
		Assertions.assertEquals(0, src.remaining());
		Assertions.assertEquals(3, dst.position());
		Assertions.assertEquals(2, dst.remaining());
		ByteBuffers.copy(src, dst);
		Assertions.assertEquals(0, src.position());
		Assertions.assertEquals(0, src.remaining());
		Assertions.assertEquals(3, dst.position());
		Assertions.assertEquals(2, dst.remaining());
	}

	@Test
	public void testCopyToEmptyDestination() {
		final ByteBuffer src = ByteBuffer.wrap(new byte[4]);
		final ByteBuffer dst = ByteBuffer.allocate(0);
		src.put(new byte[2]);
		Assertions.assertEquals(2, src.position());
		Assertions.assertEquals(2, src.remaining());
		Assertions.assertEquals(0, dst.position());
		Assertions.assertEquals(0, dst.remaining());
		ByteBuffers.copy(src, dst);
		Assertions.assertEquals(2, src.position());
		Assertions.assertEquals(2, src.remaining());
		Assertions.assertEquals(0, dst.position());
		Assertions.assertEquals(0, dst.remaining());
	}

	@Test
	public void testCopyToBiggerDestination() {
		final ByteBuffer src = ByteBuffer.wrap(new byte[2]);
		final ByteBuffer dst = ByteBuffer.allocate(10);
		dst.put(new byte[3]);
		Assertions.assertEquals(0, src.position());
		Assertions.assertEquals(2, src.remaining());
		Assertions.assertEquals(3, dst.position());
		Assertions.assertEquals(7, dst.remaining());
		ByteBuffers.copy(src, dst);
		Assertions.assertEquals(2, src.position());
		Assertions.assertEquals(0, src.remaining());
		Assertions.assertEquals(5, dst.position());
		Assertions.assertEquals(5, dst.remaining());
	}

	@Test
	public void testCopyToSmallerDestination() {
		final ByteBuffer src = ByteBuffer.wrap(new byte[5]);
		final ByteBuffer dst = ByteBuffer.allocate(2);
		Assertions.assertEquals(0, src.position());
		Assertions.assertEquals(5, src.remaining());
		Assertions.assertEquals(0, dst.position());
		Assertions.assertEquals(2, dst.remaining());
		ByteBuffers.copy(src, dst);
		Assertions.assertEquals(2, src.position());
		Assertions.assertEquals(3, src.remaining());
		Assertions.assertEquals(2, dst.position());
		Assertions.assertEquals(0, dst.remaining());
	}

}
