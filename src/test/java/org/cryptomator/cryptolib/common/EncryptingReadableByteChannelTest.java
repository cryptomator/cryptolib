package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;

class EncryptingReadableByteChannelTest {

	private ByteBuffer dstFile;
	private ReadableByteChannel srcFileChannel;
	private Cryptor cryptor;
	private FileContentCryptor contentCryptor;
	private FileHeaderCryptor headerCryptor;
	private FileHeader header;

	@BeforeEach
	public void setup() {
		dstFile = ByteBuffer.allocate(100);
		srcFileChannel = new SeekableByteChannelMock(dstFile);
		cryptor = Mockito.mock(Cryptor.class);
		contentCryptor = Mockito.mock(FileContentCryptor.class);
		headerCryptor = Mockito.mock(FileHeaderCryptor.class);
		header = Mockito.mock(FileHeader.class);
		Mockito.when(cryptor.fileContentCryptor()).thenReturn(contentCryptor);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
		Mockito.when(contentCryptor.cleartextChunkSize()).thenReturn(10);
		Mockito.when(headerCryptor.create()).thenReturn(header);
		Mockito.when(headerCryptor.encryptHeader(header)).thenReturn(ByteBuffer.wrap("hhhhh".getBytes()));
		Mockito.when(contentCryptor.encryptChunk(Mockito.any(ByteBuffer.class), Mockito.anyLong(), Mockito.any(FileHeader.class))).thenAnswer(invocation -> {
			ByteBuffer input = invocation.getArgument(0);
			String inStr = UTF_8.decode(input).toString();
			return ByteBuffer.wrap(inStr.toUpperCase().getBytes(UTF_8));
		});
	}

	@Test
	public void testEncryptionOfEmptyCleartext() throws IOException {
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream(new byte[0]));
		ByteBuffer result = ByteBuffer.allocate(10);
		try (EncryptingReadableByteChannel ch = new EncryptingReadableByteChannel(src, cryptor)) {
			int read1 = ch.read(result);
			Assertions.assertEquals(5, read1);
			int read2 = ch.read(result);
			Assertions.assertEquals(-1, read2);
			Assertions.assertArrayEquals("hhhhh".getBytes(), Arrays.copyOfRange(result.array(), 0, read1));
		}
		Mockito.verify(contentCryptor, Mockito.never()).encryptChunk(Mockito.any(), Mockito.anyLong(), Mockito.any());
	}

	@Test
	public void testEncryptionOfCleartext() throws IOException {
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("hello world 1 hello world 2".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(50);
		try (EncryptingReadableByteChannel ch = new EncryptingReadableByteChannel(src, cryptor)) {
			int read1 = ch.read(result);
			Assertions.assertEquals(32, read1);
			int read2 = ch.read(result);
			Assertions.assertEquals(-1, read2);
			Assertions.assertArrayEquals("hhhhhHELLO WORLD 1 HELLO WORLD 2".getBytes(), Arrays.copyOfRange(result.array(), 0, read1));
		}
		Mockito.verify(contentCryptor).encryptChunk(Mockito.any(), Mockito.eq(0l), Mockito.eq(header));
		Mockito.verify(contentCryptor).encryptChunk(Mockito.any(), Mockito.eq(1l), Mockito.eq(header));
	}

}