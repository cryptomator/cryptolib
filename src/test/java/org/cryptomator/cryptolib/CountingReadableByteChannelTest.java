package org.cryptomator.cryptolib;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;

import org.junit.Assert;
import org.junit.Test;

public class CountingReadableByteChannelTest {

	@Test
	public void testCounting() throws IOException {
		byte[] buf = "hello world".getBytes(US_ASCII);
		ReadableByteChannel ch = Channels.newChannel(new ByteArrayInputStream(buf));
		CountingReadableByteChannel counting = new CountingReadableByteChannel(ch);

		int first = counting.read(ByteBuffer.allocate(4));
		Assert.assertEquals(4, first);
		Assert.assertEquals(4, counting.getNumberOfBytesRead());

		int second = counting.read(ByteBuffer.allocate(0));
		Assert.assertEquals(0, second);
		Assert.assertEquals(4, counting.getNumberOfBytesRead());

		int third = counting.read(ByteBuffer.allocate(8));
		Assert.assertEquals(7, third);
		Assert.assertEquals(11, counting.getNumberOfBytesRead());

		int fourth = counting.read(ByteBuffer.allocate(4));
		Assert.assertEquals(-1, fourth);
		Assert.assertEquals(11, counting.getNumberOfBytesRead());

		Assert.assertTrue(counting.isOpen());
		counting.close();
		Assert.assertFalse(counting.isOpen());
	}

}
