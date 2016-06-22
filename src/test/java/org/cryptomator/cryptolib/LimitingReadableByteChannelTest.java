package org.cryptomator.cryptolib;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;

import org.junit.Assert;
import org.junit.Test;

public class LimitingReadableByteChannelTest {

	@Test
	public void testLimiting() throws IOException {
		byte[] buf = "hello world".getBytes(US_ASCII);
		ReadableByteChannel ch = Channels.newChannel(new ByteArrayInputStream(buf));
		ReadableByteChannel limited = new LimitingReadableByteChannel(ch, 7);
		ByteBuffer firstFourBytesBuf = ByteBuffer.allocate(4);
		ByteBuffer remainingBytesBuf = ByteBuffer.allocate(5);

		int first = limited.read(firstFourBytesBuf);
		Assert.assertEquals(4, first);
		Assert.assertEquals(4, firstFourBytesBuf.position());
		Assert.assertEquals(4, firstFourBytesBuf.limit());

		int second = limited.read(ByteBuffer.allocate(0));
		Assert.assertEquals(0, second);

		int third = limited.read(remainingBytesBuf);
		Assert.assertEquals(3, third);
		Assert.assertEquals(3, remainingBytesBuf.position());
		Assert.assertEquals(5, remainingBytesBuf.limit());

		int fourth = limited.read(ByteBuffer.allocate(10));
		Assert.assertEquals(-1, fourth);

		Assert.assertTrue(limited.isOpen());
		limited.close();
		Assert.assertFalse(limited.isOpen());

		firstFourBytesBuf.flip();
		byte[] firstFourBytes = new byte[firstFourBytesBuf.remaining()];
		firstFourBytesBuf.get(firstFourBytes);
		Assert.assertArrayEquals("hell".getBytes(US_ASCII), firstFourBytes);

		remainingBytesBuf.flip();
		byte[] remainingBytes = new byte[remainingBytesBuf.remaining()];
		remainingBytesBuf.get(remainingBytes);
		Assert.assertArrayEquals("o w".getBytes(US_ASCII), remainingBytes);
	}

}
