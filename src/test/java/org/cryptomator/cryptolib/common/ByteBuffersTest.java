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
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

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

	@Test
	public void testFillReachingBufferLimit() throws IOException {
		final ReadableByteChannel src = Mockito.mock(ReadableByteChannel.class);
		final ByteBuffer dst = ByteBuffer.allocate(10);
		Mockito.when(src.read(dst)).then(new Answer(){
			private int call = 0;

			public Object answer(InvocationOnMock invocation) {
				ByteBuffer buf = invocation.getArgument(0);
				switch (call++) {
					case 0:
						buf.put(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04});
						return 5;
					case 1:
						buf.put(new byte[]{0x06, 0x07, 0x08, 0x09, 0x0A});
						return 5;
					default:
						return -1;
				}
			}
		});
		int read = ByteBuffers.fill(src, dst);
		Mockito.verify(src, Mockito.times(2)).read(dst);
		dst.flip();
		Assertions.assertEquals(10, read);
		Assertions.assertEquals(0, dst.position());
		Assertions.assertEquals(10, dst.remaining());
		Assertions.assertArrayEquals(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x09, 0x0A}, dst.array());
	}
	
	@Test
	public void testFillReachingEof() throws IOException {
		final ReadableByteChannel src = Mockito.mock(ReadableByteChannel.class);
		final ByteBuffer dst = ByteBuffer.allocate(10);
		Mockito.when(src.read(dst)).then(new Answer(){
			private int call = 0;

			public Object answer(InvocationOnMock invocation) {
				ByteBuffer buf = invocation.getArgument(0);
				switch (call++) {
					case 0:
						buf.put(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04});
						return 5;
					case 1:
						buf.put(new byte[]{0x06, 0x07, 0x08});
						return 3;
					default:
						return -1;
				}
			}
		});
		int read = ByteBuffers.fill(src, dst);
		Mockito.verify(src, Mockito.times(3)).read(dst);
		dst.flip();
		Assertions.assertEquals(8, read);
		Assertions.assertEquals(0, dst.position());
		Assertions.assertEquals(8, dst.remaining());
		Assertions.assertArrayEquals(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x06, 0x07, 0x08, 0x00, 0x00}, dst.array());
	}

	@Test
	public void testFillStartingAtEof() throws IOException {
		final ReadableByteChannel src = Mockito.mock(ReadableByteChannel.class);
		final ByteBuffer dst = ByteBuffer.allocate(10);
		Mockito.when(src.read(dst)).thenReturn(-1);
		int read = ByteBuffers.fill(src, dst);
		Mockito.verify(src, Mockito.times(1)).read(dst);
		dst.flip();
		Assertions.assertEquals(0, read);
		Assertions.assertEquals(0, dst.position());
		Assertions.assertEquals(0, dst.remaining());
		Assertions.assertArrayEquals(new byte[10], dst.array());
	}

}
