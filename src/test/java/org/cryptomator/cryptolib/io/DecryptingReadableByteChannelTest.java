package org.cryptomator.cryptolib.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

public class DecryptingReadableByteChannelTest {

	private Cryptor cryptor;
	private FileContentCryptor contentCryptor;
	private FileHeaderCryptor headerCryptor;
	private FileHeader header;

	@Before
	public void setup() {
		cryptor = Mockito.mock(Cryptor.class);
		contentCryptor = Mockito.mock(FileContentCryptor.class);
		headerCryptor = Mockito.mock(FileHeaderCryptor.class);
		header = Mockito.mock(FileHeader.class);
		Mockito.when(cryptor.fileContentCryptor()).thenReturn(contentCryptor);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		Mockito.when(contentCryptor.ciphertextChunkSize()).thenReturn(10);
		Mockito.when(contentCryptor.cleartextChunkSize()).thenReturn(10);
		Mockito.when(headerCryptor.headerSize()).thenReturn(5);
		Mockito.when(headerCryptor.decryptHeader(Mockito.any(ByteBuffer.class))).thenReturn(header);
		Mockito.when(contentCryptor.decryptChunk(Mockito.any(ByteBuffer.class), Mockito.anyLong(), Mockito.any(FileHeader.class), Mockito.anyBoolean())).thenAnswer(new Answer<ByteBuffer>() {

			@Override
			public ByteBuffer answer(InvocationOnMock invocation) throws Throwable {
				ByteBuffer input = invocation.getArgumentAt(0, ByteBuffer.class);
				String inStr = StandardCharsets.UTF_8.decode(input).toString();
				return ByteBuffer.wrap(inStr.toLowerCase().getBytes(StandardCharsets.UTF_8));
			}

		});
	}

	@Test
	public void testDecryptionAndPaddingRemoval() throws IOException {
		Mockito.when(header.getFilesize()).thenReturn(15l);
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("hhhhhTOPSECRET!TOPSECRET!PPPPPPPPPP".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(20);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(src, cryptor, true)) {
			int read1 = ch.read(result);
			Assert.assertEquals(15, read1);
			int read2 = ch.read(result);
			Assert.assertEquals(-1, read2);
			Assert.assertArrayEquals("topsecret!topse".getBytes(), Arrays.copyOfRange(result.array(), 0, read1));
		}
	}

	@Test
	public void testDecryptionWithPhysicalEOF() throws IOException {
		Mockito.when(header.getFilesize()).thenReturn(100l);
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("hhhhhTOPSECRET!TOPSECRET!".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(30);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(src, cryptor, true)) {
			int read1 = ch.read(result);
			Assert.assertEquals(20, read1);
			int read2 = ch.read(result);
			Assert.assertEquals(-1, read2);
			Assert.assertArrayEquals("topsecret!topsecret!".getBytes(), Arrays.copyOfRange(result.array(), 0, read1));
		}
	}

}
