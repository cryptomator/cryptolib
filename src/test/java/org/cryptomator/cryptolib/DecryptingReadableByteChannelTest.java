/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

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
import java.nio.charset.Charset;
import java.util.Arrays;

public class DecryptingReadableByteChannelTest {

	private static final Charset UTF_8 = Charset.forName("UTF-8");

	private Cryptor cryptor;
	private FileContentCryptor contentCryptor;
	private FileHeaderCryptor headerCryptor;
	private FileHeader header;

	@BeforeEach
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
		Mockito.when(contentCryptor.decryptChunk(Mockito.any(ByteBuffer.class), Mockito.anyLong(), Mockito.any(FileHeader.class), Mockito.anyBoolean())).thenAnswer(invocation -> {
			ByteBuffer input = invocation.getArgument(0);
			String inStr = UTF_8.decode(input).toString();
			return ByteBuffer.wrap(inStr.toLowerCase().getBytes(UTF_8));
		});
	}

	@Test
	public void testDecryption() throws IOException {
		ReadableByteChannel src = Channels.newChannel(new ByteArrayInputStream("hhhhhTOPSECRET!TOPSECRET!".getBytes()));
		ByteBuffer result = ByteBuffer.allocate(30);
		try (DecryptingReadableByteChannel ch = new DecryptingReadableByteChannel(src, cryptor, true)) {
			int read1 = ch.read(result);
			Assertions.assertEquals(20, read1);
			int read2 = ch.read(result);
			Assertions.assertEquals(-1, read2);
			Assertions.assertArrayEquals("topsecret!topsecret!".getBytes(), Arrays.copyOfRange(result.array(), 0, read1));
		}
	}

}
