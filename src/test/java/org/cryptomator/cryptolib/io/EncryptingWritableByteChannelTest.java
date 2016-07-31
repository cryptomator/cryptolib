/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
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

public class EncryptingWritableByteChannelTest {

	private static final SecureRandom RANDOM_MOCK = new SecureRandom() {

		@Override
		public synchronized void nextBytes(byte[] bytes) {
			Arrays.fill(bytes, (byte) 'p');
		};

		@Override
		public int nextInt(int n) {
			return n;
		};

	};

	private ByteBuffer dstFile;
	private SeekableByteChannel dstFileChannel;
	private Cryptor cryptor;
	private FileContentCryptor contentCryptor;
	private FileHeaderCryptor headerCryptor;
	private FileHeader header;

	@Before
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
		Mockito.when(headerCryptor.encryptHeader(header)).thenReturn(ByteBuffer.allocate(5));
		Mockito.when(contentCryptor.encryptChunk(Mockito.any(ByteBuffer.class), Mockito.anyLong(), Mockito.any(FileHeader.class))).thenAnswer(new Answer<ByteBuffer>() {

			@Override
			public ByteBuffer answer(InvocationOnMock invocation) throws Throwable {
				ByteBuffer input = invocation.getArgumentAt(0, ByteBuffer.class);
				String inStr = StandardCharsets.UTF_8.decode(input).toString();
				return ByteBuffer.wrap(inStr.toUpperCase().getBytes(StandardCharsets.UTF_8));
			}

		});
	}

	@Test
	public void testPadding() throws IOException {
		try (EncryptingWritableByteChannel ch = new EncryptingWritableByteChannel(dstFileChannel, cryptor, RANDOM_MOCK, 0.0, 3, 3)) {

		}
		Assert.assertArrayEquals("PPP".getBytes(), Arrays.copyOfRange(dstFile.array(), 5, 8));
	}

	@Test
	public void testEncryption() throws IOException {
		try (EncryptingWritableByteChannel ch = new EncryptingWritableByteChannel(dstFileChannel, cryptor)) {
			ch.write(StandardCharsets.UTF_8.encode("hello world 1"));
			ch.write(StandardCharsets.UTF_8.encode("hello world 2"));
		}
		Assert.assertArrayEquals("HELLO WORLD 1HELLO WORLD 2".getBytes(), Arrays.copyOfRange(dstFile.array(), 5, 31));
	}

}
