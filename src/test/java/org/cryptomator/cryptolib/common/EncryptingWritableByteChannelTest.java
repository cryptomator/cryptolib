package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;

public class EncryptingWritableByteChannelTest {

	private ByteBuffer dstFile;
	private WritableByteChannel dstFileChannel;
	private Cryptor cryptor;
	private FileContentCryptor contentCryptor;
	private FileHeaderCryptor headerCryptor;
	private FileHeader header;

	@BeforeEach
	public void setup() {
		dstFile = ByteBuffer.allocate(100);
		dstFileChannel = new SeekableByteChannelMock(dstFile);
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
			String outStr = "<" + inStr.toUpperCase() + ">";
			return UTF_8.encode(outStr);
		});
	}

	@Test
	public void testEncryption() throws IOException {
		try (EncryptingWritableByteChannel ch = new EncryptingWritableByteChannel(dstFileChannel, cryptor)) {
			ch.write(UTF_8.encode("hello world 1"));
			ch.write(UTF_8.encode("hello world 2"));
		}
		dstFile.flip();
		Assertions.assertEquals("hhhhh<HELLO WORL><D 1HELLO W><ORLD 2>", UTF_8.decode(dstFile).toString());
	}

	@Test
	public void testEncryptionOfEmptyFile() throws IOException {
		try (EncryptingWritableByteChannel ch = new EncryptingWritableByteChannel(dstFileChannel, cryptor)) {
			// empty, so write nothing
		}
		dstFile.flip();
		Assertions.assertEquals("hhhhh<>", UTF_8.decode(dstFile).toString());
	}

}
